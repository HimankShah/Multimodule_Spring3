package willydekeyser.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import willydekeyser.entity.RefreshToken;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken,Integer> {
    Optional<RefreshToken> findByToken(String token);
}