package co.edu.uni.acme.ariline.server.authorization.repository;

import co.edu.uni.acme.aerolinea.commons.entity.PassengerEntity;
import co.edu.uni.acme.aerolinea.commons.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repository interface for {@link UserEntity}.
 * <p>
 * Provides basic CRUD operations along with a custom method to find a passenger by email.
 * </p>
 */
@Repository("authorization")
public interface UserRepository extends JpaRepository<UserEntity, String> {

    /**
     * Finds a {@link UserEntity} by the passenger's email.
     *
     * @param email the email of the passenger
     * @return an {@link Optional} containing the {@link UserEntity} if found, or an empty {@link Optional} if not found
     */
    Optional<UserEntity> findByEmailUser(String email);
}
