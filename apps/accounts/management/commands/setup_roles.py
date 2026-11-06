"""
apps/accounts/management/commands/setup_roles.py
================================================
Management command to provision default Django Groups ('Customer' and 'Admin')
and assign appropriate granular model and custom permissions.
"""

from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType


class Command(BaseCommand):
    help = "Sets up default Customer and Admin groups and assigns permissions."

    def handle(self, *args, **options):
        self.stdout.write("Configuring default security groups and permissions...")

        # 1. Customer Group
        customer_group, created = Group.objects.get_or_create(name="Customer")
        if created:
            self.stdout.write(self.style.SUCCESS("Created 'Customer' group."))
        else:
            self.stdout.write("Found existing 'Customer' group.")

        customer_perm_codenames = [
            ("accounts", "add_address"),
            ("accounts", "change_address"),
            ("accounts", "delete_address"),
            ("accounts", "view_address"),
            ("products", "view_product"),
            ("orders", "add_order"),
            ("orders", "view_order"),
            ("orders", "view_orderaddress"),
        ]

        for app_label, codename in customer_perm_codenames:
            try:
                perm = Permission.objects.get(content_type__app_label=app_label, codename=codename)
                customer_group.permissions.add(perm)
            except Permission.DoesNotExist:
                self.stdout.write(self.style.WARNING(f"Permission {app_label}.{codename} not found. Run migrations first."))

        # 2. Moderator Group
        # Permission boundary: Can create and update products, but CANNOT delete products.
        moderator_group, created = Group.objects.get_or_create(name="Moderator")
        if created:
            self.stdout.write(self.style.SUCCESS("Created 'Moderator' group."))
        else:
            self.stdout.write("Found existing 'Moderator' group.")

        moderator_perm_codenames = [
            # Product management (add & change, strictly NO delete)
            ("products", "add_product"),
            ("products", "change_product"),
            ("products", "view_product"),
            # Address and order management for own account
            ("accounts", "add_address"),
            ("accounts", "change_address"),
            ("accounts", "delete_address"),
            ("accounts", "view_address"),
            ("orders", "add_order"),
            ("orders", "view_order"),
            ("orders", "view_orderaddress"),
        ]

        for app_label, codename in moderator_perm_codenames:
            try:
                perm = Permission.objects.get(content_type__app_label=app_label, codename=codename)
                moderator_group.permissions.add(perm)
            except Permission.DoesNotExist:
                self.stdout.write(self.style.WARNING(f"Permission {app_label}.{codename} not found. Run migrations first."))

        # 3. Admin Group
        admin_group, created = Group.objects.get_or_create(name="Admin")
        if created:
            self.stdout.write(self.style.SUCCESS("Created 'Admin' group."))
        else:
            self.stdout.write("Found existing 'Admin' group.")

        admin_perm_codenames = [
            # Products full management
            ("products", "add_product"),
            ("products", "change_product"),
            ("products", "delete_product"),
            ("products", "view_product"),
            # Addresses view
            ("accounts", "view_address"),
            ("accounts", "change_address"),
            ("accounts", "delete_address"),
            # Orders management & sensitive data access
            ("orders", "add_order"),
            ("orders", "change_order"),
            ("orders", "delete_order"),
            ("orders", "view_order"),
            ("orders", "view_orderaddress"),
            ("orders", "delete_orderaddress"),
            ("orders", "view_sensitive_customer_data"),
            # Audit log inspection
            ("audit_logs", "view_auditlog"),
        ]

        for app_label, codename in admin_perm_codenames:
            try:
                perm = Permission.objects.get(content_type__app_label=app_label, codename=codename)
                admin_group.permissions.add(perm)
            except Permission.DoesNotExist:
                self.stdout.write(self.style.WARNING(f"Permission {app_label}.{codename} not found. Run migrations first."))

        self.stdout.write(self.style.SUCCESS("Successfully configured groups and permissions!"))
