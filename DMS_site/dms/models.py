from django.db import models
from django.contrib.auth.models import User
from django.conf import settings
from django.dispatch import receiver
from django.db.models.signals import post_save

class Document(models.Model):
    name = models.CharField(max_length = 150)
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    file_path = models.FileField()
    public_key = models.BinaryField(max_length = 2000 ,null=True)
    private_key = models.BinaryField(max_length = 2000,null=True)

class Project(models.Model):
    project_key = models.CharField(max_length = 6, unique = True)
    project_name = models.CharField(max_length = 100)
    users = models.ManyToManyField(User, blank=True)
    admin_users = models.ManyToManyField(User, blank=True, related_name='users')
    documents = models.ManyToManyField(Document, blank=True, related_name='admin_users')


class Commentary(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, null=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    document = models.ForeignKey(Document, on_delete=models.CASCADE, null=True)
    text = models.CharField(max_length = 700)
    date = models.DateTimeField(auto_now = True)

class Log(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    date = models.DateTimeField(auto_now = True)
    act = models.CharField(max_length = 300)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, null=True)
    document = models.ForeignKey(Document, on_delete=models.CASCADE, null=True)

class Sign(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    document = models.ForeignKey(Document, on_delete=models.CASCADE, null=True)
    signature = models.BinaryField(max_length = 1000 ,null=True)

def user_directory_path(instance, filename):
    return 'user_profile_{0}/{1}'.format(instance.user.id, filename)

class Task(models.Model):
    task = models.CharField(max_length = 1500)
    dueDate = models.DateField(null=True)
    createDate = models.DateField(auto_now = True)
    menRespons = models.ForeignKey(User, related_name='menRespons', on_delete=models.CASCADE)
    taskGiver = models.ForeignKey(User, related_name='taskGiver', on_delete=models.CASCADE)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, null=True)
    finished = models.BooleanField(default=False)
