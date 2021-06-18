from schemes import AugSchemeMPL
from private_key import PrivateKey
from ec import JacobianPoint, point_to_bytes, bytes_to_point, default_ec, FieldExtBase
from fields import FieldExtBase, Fq, Fq2, Fq6, Fq12
import hashlib
import time
from pathlib import Path
import os
import json
import matplotlib.pyplot as plt
import multiprocessing


def one_sig():
    basepath = Path('files/')

    files_in_basepath = (entry for entry in basepath.iterdir() if entry.is_file())
    file_names = []

    for item in files_in_basepath:
        file_names.append(item.name)

    data = create_signature(file_names[:4], print_val=True)


def create_hash_for_file(file_name):
    sha256 = hashlib.sha256()
    BUF_SIZE = 65536

    with open(file_name, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha256.update(data)

    return sha256.digest(), sha256.hexdigest()


def create_files():
    for i in range(100):
        with open('files/version_{}'.format(i), 'wb') as write_file:
            write_file.write(os.urandom(10000000))


def research():
    basepath = Path('files/')

    files_in_basepath = (entry for entry in basepath.iterdir() if entry.is_file())
    file_names = []

    for item in files_in_basepath:
        file_names.append(item.name)
        # list_of_hashes.append(create_hash_for_file(item))

    tasks = []
    for val in range(1, len(file_names)):
        tasks.append(
            (create_signature, [file_names[:val]])
        )

    task_queue = multiprocessing.Queue()
    done_queue = multiprocessing.Queue()

    for task in tasks:
        task_queue.put(task)

    for i in range(multiprocessing.cpu_count()):
        multiprocessing.Process(target=worker, args=(task_queue, done_queue)).start()

    out_put = []

    # Get and print results
    print('Results:')
    for i in range(len(tasks)):
        data = done_queue.get()
        out_put.append(data)
        print('\t', data)

    for i in range(multiprocessing.cpu_count()):
        task_queue.put('STOP')

    with open('output_2.json', 'w') as file:
        json.dump(out_put, file)


def worker(input, output):
    for func, args in iter(input.get, 'STOP'):
        data = func(*args)
        output.put(data)


def create_sig(file_hash, message):
    sk = AugSchemeMPL.key_gen(file_hash)
    pk = sk.get_g1()

    signature_time_start = time.time()

    signature = AugSchemeMPL.sign(sk, message)

    signature_time = time.time() - signature_time_start

    return signature_time


def mul_create_signature(file_names):
    list_of_hashes = []
    signatures = []

    for item in file_names:
        list_of_hashes.append(create_hash_for_file('files/' + item))

    message = list_of_hashes[-1]

    data = {
        'doc_len': [],
        'signature_time': [],
        'step_signature_time': [],
        'aggregation_time': [],
        'final_time': []
    }

    tasks = []

    for file_hash in list_of_hashes[:-1] if list_of_hashes[:-1] else list_of_hashes:
        tasks.append(
            (create_sig, (file_hash[0], message[0]))
        )

    task_queue = multiprocessing.Queue()
    done_queue = multiprocessing.Queue()

    for task in tasks:
        task_queue.put(task)

    for i in range(multiprocessing.cpu_count()):
        multiprocessing.Process(target=worker, args=(task_queue, done_queue)).start()

    start_time = time.time()

    times = []

    # Get and print results

    for i in range(len(tasks)):
        data_from_worker = done_queue.get()
        # print(data_from_worker)
        data['step_signature_time'].append(data_from_worker)

    for i in range(multiprocessing.cpu_count()):
        task_queue.put('STOP')

    data['signature_time'] = time.time() - start_time

    #     sk: PrivateKey = AugSchemeMPL.key_gen(file_hash[0])
    #
    #     pk: JacobianPoint = sk.get_g1()
    #     pks.append(pk)
    #
    #     signature_time_start = time.time()
    #
    #     signature: JacobianPoint = AugSchemeMPL.sign(sk, message[0])
    #     signatures.append(signature)
    #
    #     signature_time = time.time() - signature_time_start
    #
    #     data['signature_time'].append(time.time() - start_time)
    #     data['step_signature_time'].append(signature_time)
    #
    #
    # ag_sig_time_start = time.time()
    # aggregate_signature: JacobianPoint = AugSchemeMPL.aggregate(signatures)
    # ag_sig_time = time.time() - ag_sig_time_start
    final_time = time.time() - start_time
    #
    data['final_time'] = final_time
    data['doc_len'] = len(list_of_hashes[:-1])
    # data['aggregation_time'] = ag_sig_time

    return data


def new_research():
    basepath = Path('files/')

    files_in_basepath = (entry for entry in basepath.iterdir() if entry.is_file())
    file_names = []

    for item in files_in_basepath:
        file_names.append(item.name)

    out_put = []

    for val in range(1, len(file_names)):
        ret = mul_create_signature(file_names[:val])
        print(ret)
        out_put.append(ret)

    with open('output_1.json', 'w') as file:
        json.dump(out_put, file)


def create_signature(file_names, print_val=False):
    margin = 8

    list_of_hashes = []
    signatures = []
    pks = []

    if print_val:
        print('documents:')
        print('{:{}}{}'.format(' ', margin, file_names))

    for item in file_names:
        list_of_hashes.append(create_hash_for_file('files/' + item))

    message = list_of_hashes[-1]

    data = {
        'doc_len': [],
        'signature_time': [],
        'step_signature_time': [],
        'aggregation_time': [],
        'final_time': []
    }

    start_time = time.time()

    i = 0

    for file_hash in list_of_hashes[:-1] if list_of_hashes[:-1] else list_of_hashes:
        sk: PrivateKey = AugSchemeMPL.key_gen(file_hash[0])

        pk: JacobianPoint = sk.get_g1()
        pks.append(pk)

        signature_time_start = time.time()

        signature: JacobianPoint = AugSchemeMPL.sign(sk, message[0])
        signatures.append(signature)

        signature_time = time.time() - signature_time_start

        i += 1

        data['signature_time'].append(time.time() - start_time)
        data['step_signature_time'].append(signature_time)

        if print_val:
            print('secret key:')
            print('{:{}}{}'.format(' ', margin, sk))

            print('private key:')
            print('{:{}}{}'.format(' ', margin, pk))

            print('signature:')
            print('{:{}}{}'.format(' ', margin, signature))

            print('time:')
            print('{:{}}{:.4}'.format(' ', margin, signature_time))

            print('step {} time {}'.format(i, time.time() - start_time))

            print('-' * 150)

    ag_sig_time_start = time.time()
    aggregate_signature: JacobianPoint = AugSchemeMPL.aggregate(signatures)
    ag_sig_time = time.time() - ag_sig_time_start
    final_time = time.time() - start_time

    data['final_time'] = final_time
    data['doc_len'] = len(list_of_hashes[:-1])
    data['aggregation_time'] = ag_sig_time

    if print_val:
        print('aggregate signature:')
        signature_bytes = aggregate_signature.to_bytes_from_point()
        print('{:{}}{}'.format(' ', margin, aggregate_signature))
        print('{:{}}{}'.format(' ', margin, int.from_bytes(signature_bytes, 'big')))

        print('aggregation time:')
        print('{:{}}{}'.format(' ', margin, ag_sig_time))

        print('final time:')
        print('{:{}}{:.4}'.format(' ', margin, final_time))

        print('-' * 150)

    return data


def create_graph():
    # Data for plotting

    with open('output_2.json', 'r') as file:
        data = json.load(file)

    doc_len = []
    doc_final_time = []
    doc_aggregation_time = []
    signature_time = []
    step_sig_time = []

    for item in data:
        # print(item)
        doc_len.append(item['doc_len'])
        doc_final_time.append(item['final_time'])
        signature_time.append(item['signature_time'][-1])
        doc_aggregation_time.append(item['aggregation_time'])
        step_sig_time.append(sum(item['step_signature_time']) / len(item['step_signature_time']))
    fig, ax = plt.subplots()
    ax.plot(doc_len,  doc_final_time, label='Общее время')
    ax.plot(doc_len,  signature_time, label='Время создания подписей')
    ax.plot(doc_len,  doc_aggregation_time, label='Время аггрегации')
    ax.plot(doc_len,  step_sig_time, label='Среднее время создания одной подписи')

    legend = ax.legend(loc='upper left')

    # legend.get_frame().set_facecolor('C0')

    ax.set(xlabel='Количество документов', ylabel='Время (сек)')
    ax.grid()

    fig.savefig("test.png")
    plt.show()


def create_graph_1():
    with open('output_2.json', 'r') as file:
        data = json.load(file)

    doc_len = []
    doc_final_time = []
    doc_aggregation_time = []
    signature_time = []
    step_sig_time = []

    for item in data:
        doc_len.append(item['doc_len'])
        doc_aggregation_time.append(item['aggregation_time'])

    with open('output_1.json', 'r') as file:
        data = json.load(file)

    for item in data:
        signature_time.append(item['signature_time'])

    doc_final_time = [one + two for one, two in zip(doc_aggregation_time, signature_time)]


    fig, ax = plt.subplots()

    ax.plot(doc_len,  doc_final_time, label='Общее время')
    ax.plot(doc_len,  signature_time, label='Время создания подписей')
    ax.plot(doc_len,  doc_aggregation_time, label='Время аггрегации')

    legend = ax.legend(loc='upper left')

    ax.set(xlabel='Количество документов', ylabel='Время (сек)')
    ax.grid()

    fig.savefig("test.png")
    plt.show()


if __name__ == '__main__':
    # research()
    # create_graph_1()
    # create_graph()
    one_sig()