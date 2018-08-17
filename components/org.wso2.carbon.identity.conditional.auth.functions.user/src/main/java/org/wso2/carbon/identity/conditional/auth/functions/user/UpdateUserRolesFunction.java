package org.wso2.carbon.identity.conditional.auth.functions.user;

import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;

import java.util.List;

/**
 * Function to update given roles for the user.
 * The purpose is to perform role assigning/deletion during dynamic authentication.
 */
@FunctionalInterface
public interface UpdateUserRolesFunction {

    /**
     * Add or delete roles for a given <code>user</code>. This will consider existing roles of the user to add only
     * non-existing roles and delete existing roles only.
     *
     * @param user          Authenticated user.
     * @param newRoles      Roles to be assigned.
     * @param deletingRoles Roles to be deleted.
     */
    void updateUserRoles(JsAuthenticatedUser user, List<String> newRoles, List<String> deletingRoles);
}
