# django imports
from django import template
from django.template.defaulttags import CommentNode

import permissions.utils
register = template.Library()


class PermissionComparisonNode(template.Node):
    """Implements a node to provide an if current user has passed permission
    for current object.
    """
    @classmethod
    def handle_token(cls, parser, token):
        bits = token.contents.split()
        context_object = None
        permission = None

        if len(bits) == 3:
            context_object = bits[2]
            permission = bits[1]
        elif len(bits) == 2:
            permission = bits[1]
        else:
            raise template.TemplateSyntaxError("'%s' tag takes one or two arguments" % bits[0])
        end_tag = 'endifhasperm'
        nodelist_true = parser.parse(('else', end_tag))
        token = parser.next_token()
        if token.contents == 'else':  # there is an 'else' clause in the tag
            nodelist_false = parser.parse((end_tag,))
            parser.delete_first_token()
        else:
            nodelist_false = CommentNode()

        return cls(permission, context_object, nodelist_true, nodelist_false)

    def __init__(self, codename, context_object, nodelist_true, nodelist_false):
        self.codename = template.Variable(codename)
        if context_object is not None:
            self.context_object = template.Variable(context_object)
        else:
            self.context_object = None
        self.nodelist_true = nodelist_true
        self.nodelist_false = nodelist_false

    def render(self, context):
        if self.context_object is not None:
            obj = self.context_object.resolve(context)
        else:
            obj = None
        codename = self.codename.resolve(context)
        request = context.get("request")
        if permissions.utils.has_permission(obj, request.user, codename):
            return self.nodelist_true.render(context)
        else:
            return self.nodelist_false.render(context)


@register.tag
def ifhasperm(parser, token):
    """This function provides functionality for the 'ifhasperm' template tag.
    """
    return PermissionComparisonNode.handle_token(parser, token)
