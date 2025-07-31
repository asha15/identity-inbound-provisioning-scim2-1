package org.wso2.carbon.identity.scim2.common.authorization;

import org.wso2.charon3.core.exceptions.BadRequestException;
import org.wso2.charon3.core.exceptions.ForbiddenException;

public interface AuthorizationValidator {

    /**
     * Validates if the current user has the required scope for the operation.
     *
     * @param resourceType The SCIM resource type (USER, GROUP, ROLE, ROLE_V2)
     * @param operation The operation being performed (CREATE, READ, UPDATE, DELETE)
     * @throws ForbiddenException if the user doesn't have the required scope
     * @throws BadRequestException if validation fails due to invalid parameters
     */
    void validateScope(String operation) throws ForbiddenException, BadRequestException;
}
