package hu.webler.weblersessioncookiebasedauthentication.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserLoginRequestModel {

    private String username;
    private String password;
}
