"""mysite URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.urls import path, include
from dms import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.index),
    path('login/', views.login),
    path('logout/', views.logout),
    path('register/', views.register),
    path('profile/<int:user_id>/', views.profile),
    path('profile/edit/', views.edit_profile),
    path('profile/change_password/', views.change_password),

    path('projects/', views.projects),
    path('projects/new_project/', views.new_project),
    path('projects/project/<str:project_key>/', views.project),
    path('projects/project/add_document/<str:project_key>/<int:document_id>/', views.add_document),
    path('projects/project_log/<str:project_key>/', views.project_log),
    path('projects/delete_project/<str:project_key>/', views.delete_project),
    path('projects/project/delete_from_project/<str:project_key>/<int:doc_id>/', views.delete_from_project),

    path('documents/', views.documents),
    path('documents/new_document/', views.new_document),
    path('documents/new_document/<str:project_key>', views.new_document),
    path('documents/delete_document/<int:doc_id>/', views.delete_document),
    path('documents/document/<int:doc_id>/', views.document),
    path('documents/download/<int:doc_id>/', views.download),
    path('documents/view/<int:doc_id>/', views.view),
    path('documents/revert_log/<int:doc_id>/<int:log_id>', views.revert_log),
    path('documents/sign_document/<int:doc_id>/', views.sign_document),
    path('documents/check_document/<int:doc_id>/', views.check_document),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
