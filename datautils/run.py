import os
import subprocess
import multiprocessing
import time
import argparse
from util.pairdata import pairdata

ida_path = "./ida/idat64"
work_dir = os.path.abspath('.')
dataset_dir = './dataset/'
strip_path = "./dataset_strip/"
SAVE_ROOT = "./extract"


def getTarget(path, prefixfilter=None):
    target = []
    for root, dirs, files in os.walk(path):
        for file in files:
            if prefixfilter is None:
                target.append(os.path.join(root, file))
            else:
                for prefix in prefixfilter:
                    if file.startswith(prefix):
                        target.append(os.path.join(root, file))
    return target


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--tool', choices=['ida', 'r2'], default='ida')
    args = parser.parse_args()

    start = time.time()
    target_list = getTarget(dataset_dir)

    pool = multiprocessing.Pool(processes=8)
    for target in target_list:
        filename = target.split('/')[-1]
        filename_strip = filename + '.strip'
        ida_input = os.path.join(strip_path, filename_strip)

        subprocess.run(['strip', '-s', target, '-o', ida_input], check=True)

        if args.tool == 'r2':
            script = os.path.join(work_dir, 'datautils/r2_process.py')
            nonstrip = os.path.join(work_dir, target)
            cmd = ['python3', script, ida_input, nonstrip, os.path.join(work_dir, SAVE_ROOT)]
            pool.apply_async(subprocess.run, args=(cmd,), kwds={'capture_output': True, 'text': True, 'timeout': 300})
        else:
            script_path = os.path.join(work_dir, "datautils/process.py")
            logfile = f'log/{filename}.log'
            cmd = [ida_path, f'-L{logfile}', '-c', '-A', f'-S{script_path}',
                   f'-oidb/{filename}.idb', ida_input]
            pool.apply_async(subprocess.call, args=(cmd,))

    pool.close()
    pool.join()
    print('[*] Features Extracting Done')

    pairdata(os.path.join(work_dir, SAVE_ROOT))

    end = time.time()
    print(f"[*] Time Cost: {end - start} seconds")
