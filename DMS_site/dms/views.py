from django.shortcuts import render, redirect
from django.contrib import auth, messages
from django.contrib.auth.forms import AuthenticationForm, UserChangeForm, PasswordChangeForm
from django.contrib.postgres.search import SearchVector
from django.conf import settings
from .models import * 
from os.path import join, exists, splitext, split
from os import mkdir, remove, urandom, listdir, rmdir, rename
import random, string
from .forms import *
from django.http import HttpResponse, FileResponse
from django.core.exceptions import ObjectDoesNotExist
from shutil import move, copyfile
from django.contrib.auth.decorators import login_required

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import cryptography.exceptions
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.keywrap import aes_key_wrap

import io

types = {
    'pdf' : 'application/pdf',
    'msword' : 'application/msword',
    'json': 'application/json',
    'ms-excel': 'application/vnd.ms-excel ',
    'xml': 'application/xml ',
    'zip': 'application/zip',
    'mp3': 'audio/mpeg',
    'png': 'image/png',
    'jpg': 'image/jpeg',
    'tiff': 'image/tiff',
    'jpeg': 'image/png',
    'rtf': 'text/rtf',
    'H261': 'video/H261',
    'JPEG': 'video/JPEG',
    'jpeg2000': 'video/jpeg2000',
    'mp4': 'video/mp4',
    'mpeg': 'video/mp4',
    'webm': 'video/webm',
}


def index(request):
    if request.user.is_authenticated:
        tasks = Task.objects.filter(menRespons = request.user, finished = False)
    else:
        tasks = None
    return render(request, 'index.html', { 'tasks' : tasks, 'user' : request.user})


def login(request):
    form = AuthenticationForm()
    if request.method == 'POST':
        form = AuthenticationForm(request, request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = auth.authenticate(username = username, password = password)
            if user is not None:
                auth.login(request, user)
                messages.success(request, 'You logged in.')
                return redirect('/')
            else:
                messages.error(request, 'No such user.')
                return redirect('/login/')
        return render(request, 'login.html', {'form' : form})
    else:
        return render(request, 'login.html', {'form' : form})
    
@login_required(login_url='/login/')
def logout(request):
    auth.logout(request)
    messages.success(request, 'You are logged off.')
    return redirect("/")

def register(request):
    form = SignUpForm()
    # form2 = SignUpPForm()
    if request.method == 'POST':
        form = SignUpForm(request.POST, request.user)
        # form2 = SignUpPForm(request.POST, request.user.profile)
        if form.is_valid():
            form.save()
            messages.success(request, 'You are registered.')
            return redirect('/')
    return render(request, 'register.html', {'form' : form})

@login_required(login_url='/login/')
def profile(request, user_id):
    user = User.objects.get(id = user_id)
    if user == request.user:
        return render(request, 'profile.html', { 'user' : user , 'Observer' : None})
    return render(request, 'profile.html', { 'user' : user , 'Observer' : True})

@login_required(login_url='/login/')
def edit_profile(request):
    form = UserCF(request.POST, instance = request.user)
    # form2 = PUserCF(request.POST, instance = request.user.profile)
    if request.method == 'POST':
        form = UserCF(request.POST, instance = request.user)
        # form2 = PUserCF(request.POST, instance = request.user.profile)
        if form.is_valid():
            # path = join(settings.MEDIA_ROOT, 'user_profile_' + str(request.user.id))
            # if not exists( path ):
                # mkdir( path )
            # print(request.POST['image'])
            # if request.POST['image'] or request.FILES['image']:
                # new_path = join(path, request.FILES['image'].name)
                # handle_uploaded_file(request.FILES['image'] , new_path)
                # request.user.profile.image = request.FILES['image']

            # obj = Profile(user = request.user, image = request.FILES['image'])
            
            # obj.user = request.user
            # obj.save()
            # obj = form2.save()
            form.save()
            # form2.save()
            messages.success(request, 'You changed information.')
            return redirect('/profile/')
    return render(request, 'edit_profile.html', { 'form' : form })

@login_required(login_url='/login/')
def change_password(request):
    form = PasswordChangeForm(user = request.user)
    if request.method == 'POST':
        form = PasswordChangeForm(data = request.POST, user = request.user)
        print(form)
        if form.is_valid():
            form.save()
            auth.update_session_auth_hash(request, form.user)
            messages.success(request, 'You changed password.')
            return redirect('/profile/')
    return render(request, 'edit_password.html', { 'form' : form })

def create_new_document(user, file):
    try:
        full_name = file.name

        while Document.objects.filter(name = full_name, author_id = user.id).exists():
            splited = splitext( full_name )
            full_name = splited[0] + '_new' + splited[-1]
        path = join(settings.MEDIA_ROOT, str(user.id))
        if not exists( path ):
            mkdir( path )
        path = join(settings.MEDIA_ROOT, str(user.id), full_name)

        handle_uploaded_file(file , path)

        private_key = rsa.generate_private_key(
                public_exponent = 65537,
                key_size = 4096,
                backend = default_backend(),
            )

        pk = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),)
        
        pbk = private_key.public_key().public_bytes(
                                            encoding = serialization.Encoding.PEM,
                                            format = serialization.PublicFormat.SubjectPublicKeyInfo,
                                            )
        document.private_key = bytearray(pk)
        document.public_key = bytearray(pbk)

        db_f = Document( name = full_name,
                         author = user,
                         file_path = path,
                         private_key = pk,
                         public_key = pbk)
        db_f.save()
        return True, db_f
    except Exception as e:
        return False, e


@login_required(login_url='/login/')
def documents(request):
    documents = Document.objects.filter(author_id = request.user.id)
    form = DocForm()
    form2 = SearchDoc()
    if request.method == 'POST':
        if 'file' in request.FILES:
            form = DocForm(request.POST, request.FILES)
            if form.is_valid():


                # f_w = PdfFileWriter()
                # f_w.addBlankPage( 595, 842 )
                # info = (data[:75] + '..') if len(data) > 75 else data


                result, data = create_new_document(request.user, request.FILES['file'])
                if result:
                    log( 'Created document', request.user, document = data )
                    return redirect('/documents/')
                else:
                    messages.error(request, data)
                    return redirect('/documents/')
                # path = join(settings.MEDIA_ROOT, str(request.user.id))
                # if not exists( path ):
                    # mkdir( path )
                # path = join(settings.MEDIA_ROOT, str(request.user.id), full_name)

                # handle_uploaded_file(request.FILES['file'] , path)

                # private_key = rsa.generate_private_key(
                        # public_exponent = 65537,
                        # key_size = 4096,
                        # backend = default_backend(),
                    # )

                # pk = private_key.private_bytes(
                            # encoding=serialization.Encoding.PEM,
                            # format=serialization.PrivateFormat.TraditionalOpenSSL,
                            # encryption_algorithm=serialization.NoEncryption(),)
                
                # pbk = private_key.public_key().public_bytes(
                                                    # encoding = serialization.Encoding.PEM,
                                                    # format = serialization.PublicFormat.SubjectPublicKeyInfo,
                                                    # )
                # document.private_key = bytearray(pk)
                # document.public_key = bytearray(pbk)

                # db_f = Document( name = full_name,
                                 # author = request.user,
                                 # file_path = path,
                                 # private_key = pk,
                                 # public_key = pbk)
                # db_f.save()

                
                # messages.success(request, 'Document created')
                
        if 'search_query' in request.POST:
            form2 = SearchDoc(request.POST)
            if form2.is_valid():
                search_query = form2.cleaned_data.get('search_query')
                documents = Document.objects.filter(name__contains = search_query)
                messages.info(request, 'You searched: ' + search_query)
            return render(request, 'documents.html', {'documents' : documents, 'form' : form, 'form2' : form2})   
        return render(request, 'documents.html', {'documents' : documents, 'form' : form, 'form2' : form2})     
    return render(request, 'documents.html', {'documents' : documents, 'form' : form, 'form2' : form2})

@login_required(login_url='/login/')
def new_document(request, project_key = None):
    form = DocForm()
    if request.method == 'POST':
        form = DocForm(request.POST, request.FILES)
        if form.is_valid():
            doc_name = splitext(request.FILES['file'].name)[0]

            if Document.objects.filter(name = doc_name, author_id = request.user.id).exists():
                messages.warning(request, 'Document name already exists')
                return redirect('/documents/')
            else:
                # f_w = PdfFileWriter()
                # f_w.addBlankPage( 595, 842 )

                path = join(settings.MEDIA_ROOT, str(request.user.id))
                if not exists( path ):
                    mkdir( path )
                path = join(settings.MEDIA_ROOT, str(request.user.id), doc_name + '.pdf')

                handle_uploaded_file(request.FILES['file'], path)


                log( 'Created document', request.user, db_f )
                messages.success(request, 'Document created')
            return redirect('/documents/')
        else:
            return render(request, 'new_document.html', {'form' : form})
    else:
        return render(request, 'new_document.html', {'form' : form})
    from reportlab.pdfgen import canvas

    response = HttpResponse(content_type='application/')
    response['Content-Disposition'] = 'attachment; filename="somefilename"'

    p = canvas.Canvas(response)

    p.drawString(20, 800, "Hello world.")

    p.showPage()
    p.save()
    return response 

def handle_uploaded_file(f, path):
    with open(path, 'wb+') as destination:
        for chunk in f.chunks():
            destination.write(chunk)

def log(act, user, document = None, project = None):
    log = Log( document = document,
           user = user,
           project = project,
           act = act)
    log.save()
    return log

@login_required(login_url='/login/')
def delete_document(request, doc_id):
    document = Document.objects.get(id = doc_id)
    remove(str(document.file_path))
    document.delete()
    messages.success(request, 'Document deleted')
    return redirect('/documents/')

@login_required(login_url='/login/')
def document(request, doc_id):
    document = Document.objects.get(id = doc_id)
    logs = Log.objects.filter(document = document).order_by('-date')
    comments = Commentary.objects.filter(document = document).order_by('-date')
    form = DocForm()
    form2 = CommentForm()
    if request.method == 'POST':
        if 'file' in request.FILES:
            form = DocForm(request.POST, request.FILES)
            if form.is_valid():
                logf = log( 'Updating document', request.user, document )
                # print(str(logf.date.strftime('%Y-%m-%d %H:%M')))
                time = str(logf.date.strftime('%Y-%m-%d %H:%M:%S')).replace(" ", "_").replace(":", "_")
                path = join(settings.LOG_ROOT, time)
                if not exists( path ):
                    mkdir( path )
                
                split_name = splitext( document.name )
                
                path = join(settings.LOG_ROOT, time , split_name[0] + '_old' + split_name[-1])
                move(str(document.file_path), path)

                name = request.FILES['file'].name

                path = split(str(document.file_path))[0] + '\\' + name

                # messages.info(request, path)

                handle_uploaded_file(request.FILES['file'], path)

                document.name = name
                document.file_path = path
                document.save()

                messages.success(request, 'Update success')

                redirect('/documents/document/' + str(doc_id))
        elif 'text' in request.POST:
            form2 = CommentForm(request.POST, request.user.id)
            if form2.is_valid():
                comment = Commentary( document = document,
                                      user = request.user,
                                      text = form2.cleaned_data.get('text') )
                comment.save()
                redirect('/documents/document/' + str(doc_id))
            
    return render(request, 'document.html', {'document' : document, 'logs' : logs, 'form' : form, 'form2' : form2, 'comments' : comments})


@login_required(login_url='/login/')
def download(request, doc_id):
    document = Document.objects.get(id = doc_id)
    file_path = str(document.file_path)
    if exists(file_path):
        with open(file_path, 'rb') as f:
            type = splitext( document.name )[-1]
            response = HttpResponse(f.read(), content_type="application/" + type[1:])
            response['Content-Disposition'] = 'attachment; filename="' + str(document.name) + '"'
            return response
    else:
        messages.error(request, 'No such file')
        return redirect('/documents/')

@login_required(login_url='/login/')
def view(request, doc_id):

    document = Document.objects.get(id = doc_id)
    # messages.info(request, document.file_path)
    file_path = str(document.file_path)
    if exists(file_path):
        doc_type = splitext( document.name )[-1]
        type = types.get(doc_type[1:], None)
        # print
        if type:
            with open(file_path, 'rb') as f:
                response = HttpResponse(f.read(), content_type=type)
                # print('inline; filename="' + str(document.name) + str(document.type) + '"')
                response['Content-Disposition'] = 'inline; filename="' + str(document.name) + '"'
                return response
        else:
            messages.warning(request, 'Cant open that type of file')
            return redirect('/documents/document/' + str(doc_id) + '/')
    else:
        messages.error(request, 'No such file')
        return redirect('/documents/document/' + str(doc_id) + '/')

def RandomKeys(length):
    return ''.join( random.choices (string.ascii_uppercase + string.ascii_lowercase + string.digits, k = length))


@login_required(login_url='/login/')
def projects(request):
    if request.method == 'POST':
        if request.POST['join project']:
            return redirect('/projects/project/' + request.POST['join project'] + '/')
    projects = Project.objects.filter(users = request.user.id)
    return render(request, 'projects.html', {'projects' : projects})


@login_required(login_url='/login/')
def new_project(request):
    nlist = [request.user.id]
    form = ProjForm(user_id_list = nlist)
    if request.method == 'POST':
        form = ProjForm(request.POST, user_id_list = nlist)
        if form.is_valid():
            project = Project( project_key = RandomKeys(6),
                               project_name = form.cleaned_data.get('project_name'))
            project.save()
            users = User.objects.filter(id__in = form.cleaned_data.get('users'))
            for o in users:
                project.users.add(o)
            project.users.add(request.user)
            project.admin_users.add(request.user)
            path = join(settings.PROJECT_ROOT, str(project.id))
            if not exists( path ):
                mkdir( path )
            log( 'Created project' , request.user, None , project)
            messages.success(request, 'Project created')
            return redirect('/projects/') 
    return render(request, 'new_project.html', {'form' : form})

@login_required(login_url='/login/')
def project(request, project_key):
    form = CommentForm()
    form2 = DocForm()
    formTask = TaskForm()
    formDone = DoneForm()

    # print(request.POST)
    # print(request.FILES)
    if not Project.objects.filter(project_key = project_key).exists():
        messages.warning(request, "Project doesn't exist")
        return redirect('/projects/')
    else:
        project = Project.objects.filter(project_key = project_key).get()
    try:
        project.users.all().get(id = request.user.id)
    except ObjectDoesNotExist:
        project.users.add(request.user)
        messages.success(request, 'You are added to the project')
    print(request.user in project.admin_users.all())
    if request.method == 'POST':
        form = CommentForm(request.POST, request.user.id)
        if 'file' in request.FILES:
            form2 = DocForm(request.POST, request.FILES)
            if form2.is_valid():
                result, data = create_new_document(request.user, request.FILES['file'])
                if result:
                    add_document(request, project.project_key, data.id)
                else:
                    messages.error(request, data)
                    return redirect('/projects/project/' + str( project.project_key ))
        elif 'text' in request.POST:
            if form.is_valid():
                comment = Commentary( project = project,
                                      user = request.user,
                                      text = form.cleaned_data.get('text') )
                comment.save()
        elif 'delete_comment' in request.POST:
            comment = Commentary.objects.get(id = request.POST['delete_comment'])
            comment.delete()
            return redirect('/projects/project/' + str( project.project_key ))
        elif 'task' in request.POST:
            formTask = TaskForm(request.POST, request.user)
            if formTask.is_valid():
                task = Task(project = project,
                            taskGiver = request.user,
                            task = formTask.cleaned_data.get('task'),
                            dueDate = formTask.cleaned_data.get('dueDate'),
                            menRespons = formTask.cleaned_data.get('menRespons'),
                            )
                task.save()
                redirect('projects/project/' + project_key)
        elif 'delete_task' in request.POST:
            task = Task.objects.get(id = request.POST['delete_task'])
            task.delete()
            return redirect('/projects/project/' + str( project.project_key ))
        elif 'taskId' in request.POST:
            formDone = DoneForm(request.POST, request.user.id)
            if formDone.is_valid():
                task = Task.objects.get(id = formDone.cleaned_data.get('taskId'))
                task.finished = True
                task.save()
                redirect('projects/project/' + project_key)
        redirect('projects/project/' + project_key)

    workers = project.users.all().exclude(id = request.user.id)
    tasksDone = Task.objects.filter(project = project, finished = True)
    tasks = Task.objects.filter(project = project, finished = False)

    comments = Commentary.objects.filter(project = project).order_by('-date')
    to_delete = project.documents.all().values('id')
    docs_to_add = Document.objects.filter(author = request.user)
    for td in to_delete:
        docs_to_add = docs_to_add.exclude(id = td['id'])
    return render(request, 'project.html', {'project' : project,
                                            'docs_to_add' : docs_to_add,
                                            'form' : form,
                                            'comments' : comments,
                                            'form2' : form2,
                                            'user' : request.user,
                                            'formTask' : formTask, 
                                            'formDone' : formDone,
                                            'Tasks' : tasks, 
                                            'TasksDone' : tasksDone, 
                                            'Workers':workers,
                                            })


@login_required(login_url='/login/')
def add_document(request, project_key, document_id):
    project = Project.objects.get(project_key = project_key)
    document = Document.objects.get(id = document_id)

    path = join(settings.PROJECT_ROOT, str(project.id))
    if not exists( path ):
        mkdir( path )
    path = join(settings.PROJECT_ROOT, str(project.id), document.name)
    # messages.info(request, path)
    move(str(document.file_path), path)
    
    document.file_path = path
    document.save()

    project.documents.add(document)

    log( 'Document added to project ',
         request.user,
         document,
         project)
    return redirect('/projects/project/' + project_key + '/')


@login_required(login_url='/login/')
def delete_project(request, project_key):
    if request.method == 'GET':
        project = Project.objects.get(project_key = project_key)
        log('Project ' + str(project.project_key) + 'deleted', request.user, None, None)
        project.delete()
        messages.success(request, 'Project deleted')
    return redirect('/projects/')


@login_required(login_url='/login/')
def delete_from_project(request, project_key, doc_id):
    project = Project.objects.get(project_key = project_key)
    document = Document.objects.get(id = doc_id)

    path = join(settings.MEDIA_ROOT, str(request.user.id))
    if not exists( path ):
        mkdir( path )
    path = join(settings.MEDIA_ROOT, str(request.user.id), document.name)
    move(str(document.file_path), path)

    document.file_path = path
    document.save()

    project.documents.remove(document)
    log( 'Document deleted from project',
         request.user,
         document,
         project)
    return redirect('/projects/project/' + project_key + '/')


@login_required(login_url='/login/')
def project_log(request, project_key):
    project = Project.objects.get(project_key = project_key)
    print(project.project_key)
    print(request.user)
    print(request.user in project.admin_users.all())
    if request.user in project.admin_users.all():
        dict_user_id_list = list(project.users.values('id'))
        user_id_list = []
        for item in dict_user_id_list:
            user_id_list.append(item['id'])
        form = ProjForm(user_id_list = user_id_list)
        if request.method == 'POST':
            if 'delete_user' in request.POST:
                project.users.remove(request.POST['delete_user'])
                project.save()
                return redirect('/projects/project_log/' + project_key + '/')
            form = ProjForm(request.POST, user_id_list = user_id_list)
            if form.is_valid():
                users = User.objects.filter(id__in = form.cleaned_data.get('users'))
                for user in users:
                    project.users.add(user)
                project.save()
                return redirect('/projects/project_log/' + project_key + '/')
        logs = Log.objects.filter(project = project).order_by('date')
    else:
        return redirect('/')
    return render(request, 'log.html', {'logs' : logs, 'project' : project, 'form' : form})

@login_required(login_url='/login/')
def sign_document(request, doc_id):
    document = Document.objects.get(id = doc_id)
    # print(document.private_key)
    # if document:
        # messages.warning(request, 'Document doesn\'t exist ')
    private_key = serialization.load_pem_private_key(
                  document.private_key,
                  password = None,
                  backend = default_backend(),
                  )
    file_path = str( document.file_path )
    
    with open(file_path, 'rb') as f:
        payload = f.read()

    signature = base64.b64encode(
        private_key.sign(
            payload,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    )

    # messages.info(request, signature)

    if not Sign.objects.filter(user = request.user, document = document).exists():
        sign_db = Sign ( user = request.user,
                         document = document,
                         signature = signature,
                        )
        sign_db.save()
    else:
        sign_db = Sign.objects.get(user = request.user,
                            document = document
                            )
        sign_db.signature = signature
        sign_db.save()
    # messages.info(request, sign_db.signature)
    messages.success(request, 'Signature created: 793793001952122580626240116454593197554141416711906 403462517351860928329848028970092109784861937005564 772497377443277594412312113446080640165555018231527 725169471298183836094505625931837220615211191152388 592212328513010425509708381')
    # messages.success(request, 'Signature created')
    

    # with open('signature.sig', 'wb') as f:
        # f.write(signature)

    return redirect('/documents/document/' + str(doc_id) + '/')

# def generate_key(request, doc_id):
    # document = Document.objects.get(id = doc_id)
    # private_key = rsa.generate_private_key(
            # public_exponent = 65537,
            # key_size = 4096,
            # backend = default_backend(),
        # )

    # with open('private.key', 'wb') as f:
        # f.write(
            # private_key.private_bytes(
                # encoding=serialization.Encoding.PEM,
                # format=serialization.PrivateFormat.TraditionalOpenSSL,
                # encryption_algorithm=serialization.NoEncryption(),
            # )
        # )

    # pk = private_key.private_bytes(
                # encoding=serialization.Encoding.PEM,
                # format=serialization.PrivateFormat.TraditionalOpenSSL,
                # encryption_algorithm=serialization.NoEncryption(),)
    # document.private_key = bytearray(pk)
    # pbk = private_key.public_key().public_bytes(
                                        # encoding = serialization.Encoding.PEM,
                                        # format = serialization.PublicFormat.SubjectPublicKeyInfo,
                                        # )
    # with open('public.pem', 'wb') as f:
        # f.write(
            # private_key.public_key().public_bytes(
                # encoding = serialization.Encoding.PEM,
                # format = serialization.PublicFormat.SubjectPublicKeyInfo,
            # )
        # )
    # document.public_key = bytearray(pbk)
    # document.save()
    # messages.success(request, 'Key generated')

    # return redirect('/documents/document/' + str(doc_id) + '/')

@login_required(login_url='/login/')
def check_document(request, doc_id):
    document = Document.objects.get(id = doc_id)
    fname = str(document.file_path)
    if not Sign.objects.filter(user = request.user, document = document).exists():
        messages.warning(request, 'No signature to match')
        return redirect('/documents/document/' + str(doc_id) + '/')
    else:
        sign = Sign.objects.get(user = request.user, document = document)
    public_key = load_pem_public_key(document.public_key, default_backend())
    # messages.info(request, sign.signature)
    # print(sign.signature)
    with open(fname, 'rb') as f:
        payload_contents = f.read()
    f = io.BytesIO(sign.signature)
    signature = base64.b64decode(f.read())
    # print(signature)
    # messages.info(request, signature)
    try:
        public_key.verify(
            signature,
            payload_contents,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        messages.success(request, 'eSign is valid')
    except cryptography.exceptions.InvalidSignature as e:
        messages.error(request, 'eSign is invalid')

    # with open('public.pem', 'rb') as f:
        # public_key = load_pem_public_key(f.read(), default_backend())

    # messages.info(request, public_key)

    # Load the payload contents and the signature.
    # with open('signature.sig', 'rb') as f:
        # signature = base64.b64decode(f.read())
    # messages.info(request, signature2)
    # Perform the verification.
    # try:
        # public_key.verify(
            # signature,
            # payload_contents,
            # padding.PSS(
                # mgf = padding.MGF1(hashes.SHA256()),
                # salt_length = padding.PSS.MAX_LENGTH,
            # ),
            # hashes.SHA256(),
        # )
        # messages.success(request, 'eSign is valid')
    # except cryptography.exceptions.InvalidSignature as e:
        # messages.error(request, 'eSign is invalid')

    return redirect('/documents/document/' + str(doc_id) + '/')

@login_required(login_url='/login/')
def revert_log(request, doc_id, log_id):
    document = Document.objects.get(id = doc_id)
    log = Log.objects.get(id = log_id)
    time = str(log.date.strftime('%Y-%m-%d %H:%M:%S')).replace(" ", "_").replace(":", "_")
    path = join(settings.LOG_ROOT, time)
    file = listdir(path)[0]
    new_file = split(str(document.file_path))
    # print(new_file)
    file_path = path + '\\' + file
    # if file == new_file[1]:
        # old_file = splitext(file)[0] + '_old' + splitext(file)[1]
        # rename(file_path, old_file)
        # move(file_path, new_file[0] + '/' + new_file[1])
    # else:
    old_file = file
    remove(new_file[0] + '\\' + new_file[1])
    move(file_path, new_file[0])
    rmdir(path)

    file_path = new_file[0] + '\\' + old_file
    document.file_path = file_path
    document.name = splitext(old_file)[0]
    document.type = splitext(old_file)[1]
    document.save()
    log.delete()
    messages.success(request, 'Log reverted')
    return redirect('/documents/document/' + str(doc_id) + '/')
