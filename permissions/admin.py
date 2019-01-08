from django.contrib import admin
from permissions.models import ObjectPermission, PrincipalRoleRelation, Role, Permission


class ObjectPermissionAdmin(admin.ModelAdmin):
    list_display = ('pk', 'role', 'permission', 'content')
    list_filter = ('role', 'permission')
    search_fields = ('content_id', 'role__codename')


admin.site.register(ObjectPermission, ObjectPermissionAdmin)


class PermissionAdmin(admin.ModelAdmin):
    list_display = ('codename', 'name', 'types')
    search_fields = ('codename', 'name')

    def types(self, obj):
        return ','.join([x.name for x in obj.content_types.all()])


admin.site.register(Permission, PermissionAdmin)


class RoleAdmin(admin.ModelAdmin):
    list_display = ('codename', 'name', 'perms')
    search_fields = ('codename', 'name')
    filter_horizontal = ('global_permissions',)

    def perms(self, obj):
        return ','.join([x.codename for x in obj.global_permissions.all()])


admin.site.register(Role, RoleAdmin)


class PrincipalRoleRelationAdmin(admin.ModelAdmin):
    # list_display = ('pk', 'role', 'user', 'group', 'content')
    list_display = ('pk', 'role', 'user', 'group', 'content_type', 'content_id')
    list_filter = ('role', 'group')
    search_fields = ('user__username', 'user__first_name', 'user__last_name', 'content_id')
    raw_id_fields = ('role', 'user', 'group')


admin.site.register(PrincipalRoleRelation, PrincipalRoleRelationAdmin)
