# coding=utf-8
import os
import math
import distutils.spawn

volatility_path = "/usr/bin/volatility"

import numpy
from sklearn.ensemble import ExtraTreesClassifier, AdaBoostClassifier, RandomForestClassifier, \
    GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neural_network import MLPClassifier
from sklearn import neighbors
from sklearn.svm import SVC

from features import malfind
from features import hollowfind
from features import countermeasure_debugger
from features import countermeasure_sandbox
from features import countermeasure_vm
from features import memory_threads
from features import memory_private
from features import memory_tag
from features import memory_protection
from features import api_hbcia_api_strings
from features import memory_is_sparse
from features import memory_high_entropy_areas
from features import code_indirect_calls
from features import code_indirect_jumps
from features import thread_delay_detect
from features import thread_priority_detect
from features import process_promote_detect
from features import memory_dga_related
from features import memory_vnc
from features import trojan_clipboard
from features import trojan_country
from features import trojan_currency
from features import trojan_propagation
from features import trojan_redirect

# important configurations for DigDogDataExtraction.py

characteristics = [
    # malfind,
    # hollowfind,

    api_hbcia_api_strings,

    code_indirect_calls,
    code_indirect_jumps,

    countermeasure_debugger,
    countermeasure_sandbox,
    countermeasure_vm,

    memory_high_entropy_areas,
    memory_is_sparse,
    memory_private,
    memory_protection,
    memory_tag,
    memory_threads,
    memory_vnc,
    memory_dga_related,

    trojan_redirect,
    trojan_propagation,
    trojan_currency,
    trojan_clipboard,
    trojan_country,

    thread_delay_detect,
    thread_priority_detect,
    process_promote_detect
]

profiles = {'winxp': 'WinXPSP2x86', 'win7': 'Win7SP1x64', 'win8': 'Win8SP1x86', 'win10': 'Win10x64_10240_17770'}
folds = 10

dbconfig = {
    'sampleFsCollectionName': 'samples_fs',
    'sampleCollectionName': 'samples',
    'resultCollectionName': 'results',
    'dumpCollectionName': 'dumps'
}

hostname = 'localhost'
port = 27017

vm = {
    # EDIT ME!
    'user': 'float',
    'password': 'toor',
    'time': 60,
    'mountSample': True,
    'showBox': False,
    'machines': {
        # EDIT ME!
        'winxp': '',
        'win7': 'window7',
        'win10': ''
    }
}

# home folder is recommended for storing tmp files
SAVE_PATH = os.environ['HOME']

# global config
HOME_PATH = "/".join(os.getcwd().split("/")[:-3])
BIN_PATH = HOME_PATH + "/codes"

# DigDog.View configuration
dot_file_path = HOME_PATH + "/DigDog/App/resources/raw.dot"
png_path = HOME_PATH + "/DigDog/App/View/source/_posts"
template_path = HOME_PATH + "/DigDog/App/resources/template.md"
public_path = HOME_PATH + "/DigDog/App/View/public"

# malicious process store path
mal_proc_path = HOME_PATH + "/MalProcessResult"

# import configurations for AutoExecution.py
quincy_malicious_path = BIN_PATH + '/malware'
quincy_benign_path = BIN_PATH + '/goodware'
csv_file = BIN_PATH + '/csv_file'
model_path = BIN_PATH + '/mytest'

# important configurations for DigDogLearn.py
CV = 3
ITERS = 100

RATIO = 0.05

CLASSIFIERS = [
    ("DecisionTree",
     DecisionTreeClassifier(max_features=None, criterion="gini"), {
         "class_weight": ["balanced", None], "max_features": ["auto", "sqrt"],
         "max_depth": [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, None]}),

    ("RandomForest",
     RandomForestClassifier(criterion="gini"),
     {"class_weight": ["balanced", None], 'n_estimators': range(10, 100, 2), "max_features": ["auto", "sqrt"]}),

    ("ExtraTrees",
     ExtraTreesClassifier(criterion="gini"),
     {"class_weight": ["balanced", None], 'n_estimators': range(10, 100, 2), "max_features": ["auto", "sqrt"]}),

    ("AdaBoost",
     AdaBoostClassifier(),
     {'n_estimators': range(10, 100, 2), 'learning_rate': numpy.arange(0.01, 1.0, 0.05)}),

    ("GradientBoosting",
     GradientBoostingClassifier(),
     {'learning_rate': numpy.arange(0.1, 1.0, 0.05), 'n_estimators': range(10, 100, 2), "max_depth": [4, 5, 6, 7, 8]}),

    ("SVM",
     SVC(),
     {"C": numpy.logspace(-2, 10, 13), "gamma": numpy.logspace(-9, 3, 13)}),

    ("KNN",
     neighbors.KNeighborsClassifier(),
     {"n_neighbors": [int(math.pow(2, y)) for y in range(1, 6)], "weights": ["uniform", "distance"]}),

    ("MLP",
     MLPClassifier(),
     {"alpha": 10.0 ** -numpy.arange(1, 7),
      "activation": {"logistic", "tanh", "relu"},
      "hidden_layer_sizes": [(x,) for x in range(4, 38, 2)]})
]

METRIC = "f1"

# important configurations for DigDogScan.py
PRECOMPUTED_MODELS = {
    "winxp": "winxp_20170502_extratrees.json",
    "win7": "win7_20170502_extratrees.json",
    "win10": "win10_20170502_extratrees.json"
}

MALICIOUS = 0
BENIGN = 1

# APIs
# VirusTotal api key
VIRUSTOTAL_KEY = "5afc4913e2e61daf9850a6c9bcb14b2b06dd144b21b3996c68f77efe65f3f270"
DGA_ARCHIVE_USER = "eGlkaWFuX2VkdV9jbg=="
DGA_ARCHIVE_PASS = "tylerallynstrollmince"

HEXDUMP_BYTES = 256
