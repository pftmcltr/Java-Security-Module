package com.example.securitymodule.enumeration;

import static com.example.securitymodule.constant.Authority.*;

public enum Role {

    ROLE_USER(USER_AUTHORITIES),
    ROLE_MANAGER(MANAGER_AUTHORITIES),
    ROLE_ADMIN(ADMIN_AUTHORITIES),
    ROLE_SUPER_ADMIN(SUPER_ADMIN_AUTHORITIES);

    private String[] authorities;

    //    Varargs - get any number of authorities.
    Role(String... authorities){
        this.authorities = authorities;
    }

    public String[] getAuthorities(){
        return authorities;
    }
}
