package com.DevTechsOne.springProj_Jwt.user;

import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.Arrays;
import java.util.List;
import static com.DevTechsOne.springProj_Jwt.user.Permissions.*;

@Getter
@NoArgsConstructor
public enum Role {

    CUSTOMER(List.of(READ_ALL_PRODUCTS)),
    ADMIN(Arrays.asList(SAVE_PRODUCT,READ_ALL_PRODUCTS));

    List<Permissions> permissionsList;

    Role(List<Permissions> permissionsList) {
        this.permissionsList = permissionsList;
    }
}
