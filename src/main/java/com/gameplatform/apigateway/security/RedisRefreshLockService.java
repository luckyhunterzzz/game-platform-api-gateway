package com.gameplatform.apigateway.security;

import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

@Service
public class RedisRefreshLockService {

    private static final String LOCK_PREFIX = "game:gateway:refresh-lock:";
    private static final String RECENT_REFRESH_PREFIX = "game:gateway:recent-refresh:";
    private static final RedisScript<Long> RELEASE_SCRIPT = new DefaultRedisScript<>(
            "if redis.call('get', KEYS[1]) == ARGV[1] then " +
                    "return redis.call('del', KEYS[1]) else return 0 end",
            Long.class
    );

    private final ReactiveStringRedisTemplate redisTemplate;

    public RedisRefreshLockService(ReactiveStringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public Mono<RefreshLock> tryAcquire(String sessionId, Duration ttl) {
        String key = lockKey(sessionId);
        String owner = UUID.randomUUID().toString();

        return redisTemplate.opsForValue()
                .setIfAbsent(key, owner, ttl)
                .filter(Boolean.TRUE::equals)
                .map(ignored -> new RefreshLock(key, owner));
    }

    public Mono<Void> release(RefreshLock lock) {
        return redisTemplate.execute(RELEASE_SCRIPT, List.of(lock.key()), List.of(lock.owner()))
                .then();
    }

    public Mono<Boolean> isRefreshInProgress(String sessionId) {
        return redisTemplate.hasKey(lockKey(sessionId));
    }

    public Mono<Boolean> wasRecentlyRefreshed(String sessionId) {
        return redisTemplate.hasKey(recentRefreshKey(sessionId));
    }

    public Mono<Void> markRecentlyRefreshed(String sessionId, Duration ttl) {
        return redisTemplate.opsForValue()
                .set(recentRefreshKey(sessionId), "1", ttl)
                .then();
    }

    private String lockKey(String sessionId) {
        return LOCK_PREFIX + sessionId;
    }

    private String recentRefreshKey(String sessionId) {
        return RECENT_REFRESH_PREFIX + sessionId;
    }

    public record RefreshLock(String key, String owner) {
    }
}
