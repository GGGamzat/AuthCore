from django.core.management.base import BaseCommand
from core.models import User, Permission, Role, UserRole
import os


class Command(BaseCommand):
    help = 'Create initial admin user with basic permissions and test users'

    def add_arguments(self, parser):
        parser.add_argument(
            '--email',
            help='Email for the superuser',
        )
        parser.add_argument(
            '--password',
            help='Password for the superuser',
        )
        parser.add_argument(
            '--no-test-users',
            action='store_true',
            default=False,
            help='Skip creating test users (editor and viewer)',
        )
        parser.add_argument(
            '--noinput',
            action='store_false',
            dest='interactive',
            default=False,
            help='Tells Django to NOT prompt the user for input of any kind.',
        )

    def handle(self, *args, **options):
        interactive = options['interactive']
        email = options['email']
        password = options['password']
        no_test_users = options['no_test_users']

        # Если email не указан, берем из переменных окружения или используем дефолтный
        if not email:
            email = os.getenv('ADMIN_EMAIL', 'admin@example.com')

        # Если пароль не указан, берем из переменных окружения или используем дефолтный
        if not password:
            password = os.getenv('ADMIN_PASSWORD', 'admin123')

        self.stdout.write('Creating initial admin user and basic data...')

        # 1. Создаем суперпользователя
        admin_user, created = User.objects.get_or_create(
            email=email,
            defaults={
                'first_name': 'Admin',
                'last_name': 'System',
                'is_admin': True,
            }
        )

        if created:
            admin_user.set_password(password)
            admin_user.save()
            self.stdout.write(self.style.SUCCESS(f'Admin user created: {email}'))
        else:
            self.stdout.write(self.style.WARNING(f'Admin user already exists: {email}'))
            # Обновляем пароль если был передан новый
            if options['password']:
                admin_user.set_password(password)
                admin_user.save()
                self.stdout.write('Password updated')

        # 2. Создаем базовые разрешения
        permissions_data = [
            # Посты
            ('view_posts', 'View Posts', 'Can view posts'),
            ('create_posts', 'Create Posts', 'Can create new posts'),
            ('edit_posts', 'Edit Posts', 'Can edit posts'),
            ('delete_posts', 'Delete Posts', 'Can delete posts'),

            # Админка
            ('access_admin_panel', 'Access Admin Panel', 'Can access admin panel'),
            ('manage_users', 'Manage Users', 'Can manage users'),
            ('manage_roles', 'Manage Roles', 'Can manage roles'),
            ('manage_permissions', 'Manage Permissions', 'Can manage permissions'),
            ('assign_roles', 'Assign Roles', 'Can assign roles to users'),
        ]

        permissions = {}
        for codename, name, description in permissions_data:
            perm, created = Permission.objects.get_or_create(
                codename=codename,
                defaults={'name': name, 'description': description}
            )
            permissions[codename] = perm
            if created:
                self.stdout.write(f'Created permission: {name}')

        # 3. Создаем роль Admin со всеми правами
        admin_role, created = Role.objects.get_or_create(
            name='Admin',
            defaults={'description': 'Full system access'}
        )

        if created:
            all_permissions = Permission.objects.all()
            admin_role.permissions.set(all_permissions)
            self.stdout.write('Created Admin role with all permissions')

        # 4. Назначаем роль Admin суперпользователю
        user_role, created = UserRole.objects.get_or_create(
            user=admin_user,
            role=admin_role
        )
        if created:
            self.stdout.write('Assigned Admin role to admin user')

        # 5. Создаем тестовых пользователей (если не отключено)
        if not no_test_users:
            self._create_test_users(permissions)

        self.stdout.write(self.style.SUCCESS('\nInitial setup completed!'))
        self.stdout.write(f'\nAPI: http://localhost:8000/api/')
        self.stdout.write(f'Admin login: {email} / {password}')
        if not no_test_users:
            self.stdout.write(f'Editor login: editor@example.com / editor123')
            self.stdout.write(f'Viewer login: viewer@example.com / viewer123')

    def _create_test_users(self, permissions):
        self.stdout.write('\nCreating test users...')

        # Создаем роль Editor
        editor_role, created = Role.objects.get_or_create(
            name='Editor',
            defaults={'description': 'Can manage all posts'}
        )

        if created:
            editor_permissions = [
                permissions['view_posts'],
                permissions['create_posts'],
                permissions['edit_posts'],
                permissions['delete_posts'],
            ]
            editor_role.permissions.set(editor_permissions)
            self.stdout.write('Created Editor role')

        # Создаем тестового редактора
        editor_email = 'editor@example.com'
        editor_password = 'editor123'
        editor_user, created = User.objects.get_or_create(
            email=editor_email,
            defaults={
                'first_name': 'Alex',
                'last_name': 'Editor',
            }
        )

        if created:
            editor_user.set_password(editor_password)
            editor_user.save()
            self.stdout.write(f'Created editor: {editor_email} / {editor_password}')
        else:
            # Если уже существует, обновляем пароль
            editor_user.set_password(editor_password)
            editor_user.save()
            self.stdout.write(f'Updated editor: {editor_email} / {editor_password}')

        # Назначаем роль Editor
        UserRole.objects.get_or_create(user=editor_user, role=editor_role)
        self.stdout.write('Assigned Editor role to editor user')

        # Создаем роль Viewer
        viewer_role, created = Role.objects.get_or_create(
            name='Viewer',
            defaults={'description': 'Can only view content'}
        )

        if created:
            viewer_permissions = [permissions['view_posts']]
            viewer_role.permissions.set(viewer_permissions)
            self.stdout.write('Created Viewer role')

        # Создаем тестового просмотрщика
        viewer_email = 'viewer@example.com'
        viewer_password = 'viewer123'
        viewer_user, created = User.objects.get_or_create(
            email=viewer_email,
            defaults={
                'first_name': 'John',
                'last_name': 'Viewer',
            }
        )

        if created:
            viewer_user.set_password(viewer_password)
            viewer_user.save()
            self.stdout.write(f'Created viewer: {viewer_email} / {viewer_password}')
        else:
            # Если уже существует, обновляем пароль
            viewer_user.set_password(viewer_password)
            viewer_user.save()
            self.stdout.write(f'Updated viewer: {viewer_email} / {viewer_password}')

        # Назначаем роль Viewer
        UserRole.objects.get_or_create(user=viewer_user, role=viewer_role)
        self.stdout.write('Assigned Viewer role to viewer user')