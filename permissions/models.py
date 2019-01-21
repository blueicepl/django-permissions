# django imports
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.fields import GenericForeignKey
from django.db import models
from django.contrib.auth.models import Group
from django.contrib.contenttypes.models import ContentType
from django.db.models import Q
from django.utils.translation import ugettext_lazy as _

# permissions imports
# import permissions.utils


class PermissionManager(models.Manager):

    def get_by_natural_key(self, codename):
        return self.get(codename=codename)


class Permission(models.Model):
    """A permission which can be granted to users/groups and objects.

    **Attributes:**

    name
        The unique name of the permission. This is displayed to users.

    codename
        The unique codename of the permission. This is used internal to
        identify a permission.

    content_types
        The content types for which the permission is active. This can be
        used to display only reasonable permissions for an object.
    """
    name = models.CharField(_(u"Name"), max_length=100, unique=True)
    codename = models.CharField(_(u"Codename"), max_length=100, unique=True)
    content_types = models.ManyToManyField(ContentType, verbose_name=_(u"Content Types"), blank=True,
                                           related_name="content_types")

    objects = PermissionManager()

    def __unicode__(self):
        return u"%s (%s)" % (self.name, self.codename)

    def natural_key(self):
        return self.codename,


class ObjectPermission(models.Model):
    """Grants permission for a role and an content object (optional).

    **Attributes:**

    role
        The role for which the permission is granted.

    permission
        The permission which is granted.

    content
        The object for which the permission is granted.
    """
    role = models.ForeignKey("Role", verbose_name=_(u"Role"), blank=True, null=True)
    permission = models.ForeignKey(Permission, verbose_name=_(u"Permission"))

    content_type = models.ForeignKey(ContentType, verbose_name=_(u"Content type"))
    content_id = models.PositiveIntegerField(verbose_name=_(u"Content id"))
    content = GenericForeignKey(ct_field="content_type", fk_field="content_id")

    def __unicode__(self):
        return u"%s / %s / %s - %s" % (self.permission.name, self.role, self.content_type, self.content_id)

    class Meta:
        unique_together = ('role', 'permission', 'content_type', 'content_id')


class ObjectPermissionInheritanceBlock(models.Model):
    """Blocks the inheritance for specific permission and object.

    **Attributes:**

    permission
        The permission for which inheritance is blocked.

    content
        The object for which the inheritance is blocked.
    """
    permission = models.ForeignKey(Permission, verbose_name=_(u"Permission"))

    content_type = models.ForeignKey(ContentType, verbose_name=_(u"Content type"))
    content_id = models.PositiveIntegerField(verbose_name=_(u"Content id"))
    content = GenericForeignKey(ct_field="content_type", fk_field="content_id")

    def __unicode__(self):
        return u"%s / %s - %s" % (self.permission, self.content_type, self.content_id)


class RoleManager(models.Manager):

    def get_by_natural_key(self, codename):
        return self.get(codename=codename)


class Role(models.Model):
    """A role gets permissions to do something. Principals (users and groups)
    can only get permissions via roles.

    **Attributes:**

    name
        The unique name of the role
    """
    name = models.CharField(max_length=100, unique=True)
    codename = models.CharField(_(u"Codename"), max_length=100, unique=True)
    global_permissions = models.ManyToManyField(Permission, verbose_name=_(u"Global permissions"),
                                                blank=True, related_name="roles_globals")

    objects = RoleManager()

    class Meta:
        ordering = ("name", )

    def __unicode__(self):
        return self.name

    def natural_key(self):
        return self.codename,

    # noinspection PyUnusedLocal
    def add_principal(self, principal, content=None):
        """Addes the given principal (user or group) ot the Role.
        """
        from permissions.utils import add_role
        return add_role(principal, self)

    def get_groups(self, content=None):
        """Returns all groups which has this role assigned. If content is given
        it returns also the local roles.
        """
        if content:
            ctype = ContentType.objects.get_for_model(content)
            prrs = PrincipalRoleRelation.objects\
                .filter(role=self).filter(Q(content_id__isnull=True) | Q(content_id=content.id))\
                .filter(Q(content_type__isnull=True) | Q(content_type=ctype))\
                .exclude(group__isnull=True)
        else:
            prrs = PrincipalRoleRelation.objects.filter(role=self, content_id__isnull=True,
                                                        content_type__isnull=True).exclude(group__isnull=True)

        return [prr.group for prr in prrs]

    def get_users(self, content=None):
        """Returns all users which has this role assigned. If content is given
        it returns also the local roles.
        """
        if content:
            ctype = ContentType.objects.get_for_model(content)
            prrs = PrincipalRoleRelation.objects\
                .filter(role=self, content_id__in=(None, content.id), content_type__in=(None, ctype))\
                .exclude(user=None)
        else:
            prrs = PrincipalRoleRelation.objects.filter(role=self, content_id=None, content_type=None)\
                .exclude(user=None)

        return [prr.user for prr in prrs]


class PrincipalRoleRelation(models.Model):
    """A role given to a principal (user or group). If a content object is
    given this is a local role, i.e. the principal has this role only for this
    content object. Otherwise it is a global role, i.e. the principal has
    this role generally.

    user
        A user instance. Either a user xor a group needs to be given.

    group
        A group instance. Either a user xor a group needs to be given.

    role
        The role which is given to the principal for content.

    content
        The content object which gets the local role (optional).
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, verbose_name=_(u"User"), blank=True, null=True)
    group = models.ForeignKey(Group, verbose_name=_(u"Group"), blank=True, null=True)
    role = models.ForeignKey(Role, verbose_name=_(u"Role"))

    content_type = models.ForeignKey(ContentType, verbose_name=_(u"Content type"), blank=True, null=True)
    content_id = models.PositiveIntegerField(verbose_name=_(u"Content id"), blank=True, null=True)
    content = GenericForeignKey(ct_field="content_type", fk_field="content_id")

    def __unicode__(self):
        if self.user:
            principal = self.user.username
        else:
            principal = self.group

        return u"%s - %s" % (principal, self.role)

    def natural_key(self):
        return self.role, self.user, self.group, self.content_type, self.content_id

    def get_principal(self):
        """Returns the principal.
        """
        return self.user or self.group

    def set_principal(self, principal):
        """Sets the principal.
        """
        user_class = get_user_model()
        if isinstance(principal, user_class):
            self.user = principal
        else:
            self.group = principal

    principal = property(get_principal, set_principal)

    class Meta:
        indexes = [
            models.Index(fields=['user_id', 'group_id', 'role_id', 'content_type_id']),
            models.Index(fields=['user_id', 'content_type_id'])
        ]
