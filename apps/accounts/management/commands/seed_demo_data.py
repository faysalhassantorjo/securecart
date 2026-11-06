"""
apps/accounts/management/commands/seed_demo_data.py
===================================================
Seeds initial demonstration data:
- Customer and Admin groups and permissions
- Admin superuser ('admin' / 'AdminPass123!')
- Customer users ('customer1' / 'CustomerPass123!', 'customer2' / 'CustomerPass123!')
- Sample security & privacy hardware products
- Saved address with AES-256-GCM encrypted contact details
"""

from decimal import Decimal
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User, Group
from django.core.management import call_command
from apps.products.models import Product
from apps.accounts.models import Address
from apps.core.encryption import encrypt_value


class Command(BaseCommand):
    help = "Seeds initial demo users, groups, products, and addresses."

    def handle(self, *args, **options):
        self.stdout.write("Seeding demo data...")

        # 1. Setup groups and permissions
        call_command("setup_roles")

        customer_group = Group.objects.get(name="Customer")
        admin_group = Group.objects.get(name="Admin")

        # 2. Create Admin user
        admin_user, created = User.objects.get_or_create(
            username="admin",
            defaults={"email": "admin@securecart.local", "is_staff": True, "is_superuser": True},
        )
        if created:
            admin_user.set_password("AdminPass123!")
            admin_user.save()
            admin_user.groups.add(admin_group)
            self.stdout.write(self.style.SUCCESS("Created admin user: 'admin' (Password: AdminPass123!)"))
        else:
            self.stdout.write("Admin user already exists.")

        # 3. Create Customer 1
        c1, created = User.objects.get_or_create(
            username="customer1",
            defaults={"email": "customer1@example.com"},
        )
        if created:
            c1.set_password("CustomerPass123!")
            c1.save()
            c1.groups.add(customer_group)
            self.stdout.write(self.style.SUCCESS("Created customer: 'customer1' (Password: CustomerPass123!)"))

        # 4. Create Customer 2
        c2, created = User.objects.get_or_create(
            username="customer2",
            defaults={"email": "customer2@example.com"},
        )
        if created:
            c2.set_password("CustomerPass123!")
            c2.save()
            c2.groups.add(customer_group)
            self.stdout.write(self.style.SUCCESS("Created customer: 'customer2' (Password: CustomerPass123!)"))

        # 5. Create Sample Products
        demo_products = [
            {
                "name": "Secure Hardware Wallet",
                "description": "Military-grade CC EAL6+ certified secure element hardware wallet.",
                "price": Decimal("129.99"),
                "stock_quantity": 50,
            },
            {
                "name": "Privacy Screen Filter (15.6 inch)",
                "description": "Anti-glare, anti-scratch, limits viewing angle to +/- 30 degrees.",
                "price": Decimal("34.50"),
                "stock_quantity": 100,
            },
            {
                "name": "Encrypted USB Flash Drive (128GB)",
                "description": "Hardware-encrypted USB 3.0 flash drive with onboard PIN keypad.",
                "price": Decimal("79.99"),
                "stock_quantity": 30,
            },
            {
                "name": "YubiKey 5C NFC",
                "description": "Multi-protocol hardware authenticator supporting FIDO2/WebAuthn.",
                "price": Decimal("55.00"),
                "stock_quantity": 40,
            },
        ]

        for p_data in demo_products:
            p, created = Product.objects.get_or_create(
                name=p_data["name"],
                defaults=p_data,
            )
            if created:
                self.stdout.write(f"Created product: {p.name}")

        # 6. Create Saved Address for customer1 with encrypted fields
        if not Address.objects.filter(user=c1).exists():
            Address.objects.create(
                user=c1,
                full_name="Alice Customer",
                street_address="742 Evergreen Terrace",
                city="Springfield",
                postal_code="97477",
                encrypted_phone=encrypt_value("+1-555-019-2834"),
                encrypted_email=encrypt_value("alice.customer@example.com"),
            )
            self.stdout.write(self.style.SUCCESS("Created demo encrypted address for customer1."))

        self.stdout.write(self.style.SUCCESS("Demo seeding completed successfully!"))
