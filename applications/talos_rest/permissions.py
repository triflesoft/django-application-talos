from rest_framework import permissions

class IsAuthenticated(permissions.BasePermission):
    message = 'you do not have a permission'

    def has_permission(self, request, view):
        authentication_evidences = ('authenticated',
                                    'knowledge_factor',
                                    'knowledge_factor_password',
                                    'ownership_factor',
                                    'ownership_factor_otp_token',
                                    )
        provided_evidences = request.principal._evidences_effective

        print(authentication_evidences)
        print(provided_evidences)

        result = []
        for evidence in authentication_evidences:
            if evidence not in provided_evidences:
                result.append(evidence)

        if len(result) > 0:
            self.message = result
            return False
        return True