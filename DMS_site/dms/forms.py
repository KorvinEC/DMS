from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django.contrib.auth.models import User
from django.contrib import auth
from dms.views import *

class DocForm(forms.Form):
    # document_name = forms.CharField(max_length = 100)
    file = forms.FileField()

def define_choices(user_id_list):
    users_id = list(User.objects.all().values_list('id').exclude(id__in = user_id_list))
    users_name = list(User.objects.all().values_list('first_name','last_name').exclude(id__in = user_id_list))
    users_id_list = []
    for id in users_id:
        users_id_list.append(id[0])
    full_names = []
    for fn, ln in users_name:
        full_names.append(fn + ' ' + ln)
    choices = []
    for i in range(len( users_id_list )):
        choices.append([users_id_list[i], full_names[i]])
    return choices

class ProjForm(forms.Form):
    project_name = forms.CharField(max_length = 100, required=False)
    def __init__(self, *args, **kwargs):
        user_id_list = kwargs.pop('user_id_list')
        super(ProjForm, self).__init__(*args, **kwargs)
        self.fields['users'] = forms.MultipleChoiceField( required=False,
            choices = define_choices(user_id_list) )
        

class SignUpForm(UserCreationForm):
    first_name = forms.CharField(max_length=30, required=False, help_text='Optional.')
    last_name = forms.CharField(max_length=30, required=False, help_text='Optional.')
    email = forms.EmailField(max_length=254, required=False, help_text='Optional.' )
    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'password1', 'password2')

# class SignUpPForm(forms.Form):
    # image = forms.ImageField(required=False, help_text='Optional.')

    # class Meta:
        # model = Profile
        # fields = ('image',)

class UserCF(UserChangeForm):
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email', 'password')

# class PUserCF(forms.ModelForm):
    # class Meta:
        # model = Profile
        # fields = ('image',)

class SearchDoc(forms.Form):
    search_query = forms.CharField(max_length = 100)

class CommentForm(forms.ModelForm):
    class Meta:
        model = Commentary
        fields = ('text',)


class TaskForm(forms.ModelForm):
    dueDate = forms.DateField(required=False)
    class Meta:
        model = Task
        fields = ('task','menRespons')

class DoneForm(forms.Form):
    taskId = forms.CharField()