package hu.webler.weblersessioncookiebasedauthentication.persistence;

import hu.webler.weblersessioncookiebasedauthentication.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findUserByUsername(String username);
    Optional<User> findUserByAuthToken(String authToken);
}
