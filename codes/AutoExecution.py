import os
import sys
import time

import DigDogConfig as Config
import logging
from util.DigDogUtils import set_up_logging

sys.path.append(os.path.abspath("../codes/"))


def feedSamples(cmdstrings, step1, judge):
    '''
    Modify the process of feeding samples to mongodatabase by construct cmd command.
    Interact with users.
    :param cmdstrings: constructed command: "python " + Config.code_path + "DigDogDataExtraction.py " + database_name
    :param step1: constructed command: " feedSamples "
    :param judge: overwrite or not
    :return:
    '''
    classification = raw_input("[+]Is the sample malicious or benign? m or M for malicious and b or B for benign: ")
    name1 = raw_input("[+]Sample name :")
    if classification == "m" or classification == "M":
        if judge == "n" or judge == "N":
            os.system(cmdstrings + step1 + Config.quincy_malicious_path + name1 + " malicious")
        else:
            os.system(cmdstrings + step1 + Config.quincy_malicious_path + name1 + " malicious --overwrite")
    elif classification == "b" or classification == "B":
        if judge == "n" or judge == "N":
            os.system(cmdstrings + step1 + Config.quincy_benign_path + name1 + " benign")
        else:
            os.system(cmdstrings + step1 + Config.quincy_benign_path + name1 + " benign --overwrite")
    logging.info("[+]Loading...")


def generateDumps(cmdstrings, step2, judge):
    '''
    Modify the generation of sample dumps with the calls of VirtualBox
    The path of dump result file is defined in DigDogConfig.py
    :param cmdstrings: constructed command
    :param step2: constructed command: " generateDumps "
    :param judge: overwrite or not
    :return:
    '''
    if judge == "n" or judge == "N":
        os.system(cmdstrings + step2 + Config.dump_result_path)
    elif judge == "y" or judge == "Y":
        os.system(cmdstrings + step2 + Config.dump_result_path + " --overwrite")
    logging.info("[+]Loading...")


def createGroundTruth(cmdstrings, step3):
    '''
    Modify the creation of groundtruth with appointed yara signature files
    :param cmdstrings: constructed command
    :param step3: constructed command: " createGroundTruth "
    :return:
    '''
    name3 = raw_input("[+]Please input the name of signature file: ")
    os.system(cmdstrings + step3 + Config.quincy_malicious_path + name3)
    logging.info("[+]Loading...")


def addGroundTruth(cmdstrings, step4):
    '''
    Modify the process of adding groundtruth data to database
    Maybe we could accomplish autoload the json file generated in createGroundTruth
    :param cmdstrings: constructed command
    :param step4: constructed command: " addGroundTruth "
    :return:
    '''
    name4 = raw_input("[+]Please input the name of json file: ")
    os.system(cmdstrings + step4 + Config.json_file_path + name4)
    logging.info("[+]Loading...")


def extractFeatures(cmdstrings, step5, judge):
    '''
    Modify the process of features extraction
    :param cmdstrings: constructed command
    :param step5: constructed command: " extractFeatures "
    :param judge: overwrite or not
    :return:
    '''
    if judge == "n" or judge == "N":
        os.system(cmdstrings + step5)
    elif judge == "y" or judge == "Y":
        os.system(cmdstrings + step5 + " --overwrite")
    logging.info("[+]Loading...")


def exportRawData(cmdstrings, step6):
    '''
    Modify the raw data file export, return a csv file in appointed directory
    :param cmdstrings: constructed command
    :param step6: constructed command: " exportRawData "
    :return:
    '''
    name6 = raw_input("[+]Please input the name of the csv file: ")
    os.system(cmdstrings + step6 + Config.csv_file + name6)
    logging.info("[+]Loading...")
    return name6


def QLearn(name6):
    '''
    Modify the interaction with users in the process of QuincyLearn
    :param name6: the name of csv file which is generated in the last step
    :return:
    '''
    classifier = raw_input('[+]Please choose the classifier: ')
    parameters = [" -v", " --undersampling", " --scaling", " --feature_selection"]
    model_name = raw_input('[+]Please input the name of final_model: ')
    final_cmdline = "python " + Config.code_path + "DigDogLearn.py " + " --classifier=" + classifier
    for i in range(len(parameters)):
        result = raw_input("[+]" + parameters[i] + " is chosen or not? y/Y for chosen and n/N for not: ")
        if result == "n" or result == "N":
            continue
        elif result == "y" or result == "Y":
            final_cmdline += parameters[i]
    final_cmdline += " " + Config.csv_file + name6 + " " + model_name + " " + Config.model_path
    print final_cmdline
    os.system(final_cmdline)


def QScan(dump_name, custom_model, profile):
    '''
    Modify the interaction with users in the process of QuincyScan
    :param dump_name: the complete path of the dump file must be input by the user, usually ending with .gz
    :param custom_model: the complete path of the json file must be input by the user, ending with .json
    :param profile: the version of the system of the dump file
    :return:
    '''
    parameters = [" --prefilter", " -v", " --with_malfind", " --with_hollowfind", " --with_virustotal",
                  " --with_netscan"]
    final_cmdline = "python " + Config.code_path + "DigDogScan.py " + dump_name + " --custom_model=" \
                    + Config.model_path + custom_model
    for i in range(len(parameters)):
        result = raw_input("[+]" + parameters[i] + " is chosen or not? y/Y for chosen and n/N for not: ")
        if result == "n" or result == "N":
            continue
        elif result == "y" or result == "Y":
            final_cmdline += parameters[i]
    final_cmdline += " --profile=" + profile
    os.system(final_cmdline)


def Developer_Mode():
    '''
    This is the complete process of the developer mode
    feedSamples ->
    generateDumps ->
    createGroundTruth ->
    addGroundTruth ->
    extractFeatures ->
    exportRawData
    :return:
    '''
    database_name = raw_input('[+]Please input the name of database: ')
    cmdstrings = "python " + Config.code_path + "DigDogDataExtraction.py " + database_name

    step1 = " feedSamples "
    step2 = " generateDumps "
    step3 = " createGroundTruth "
    step4 = " addGroundTruth "
    step5 = " extractFeatures "
    step6 = " exportRawData "
    '''
    logging.info('[+]Step1: feedSamples Start...')
    while True:
        judge = raw_input('[+]Overwrite or not? y/Y for yes and n/N for no: ')
        feedSamples(cmdstrings, step1, judge)
        stop = raw_input('[+]Continue or stop? y/Y for continue and n/N for stop: ')
        if stop == "y" or stop == "Y":
            continue
        elif stop == "n" or stop == "N":
            break
    
    logging.info('[-]Step1 Finished!')

    logging.info('[+]Step2: generateDumps Start...')
    judge = raw_input('[+]Overwrite or not? y/Y for yes and n/N for no: ')
    generateDumps(cmdstrings, step2, judge)
    logging.info('[-]Step2 Finished!')

    logging.info('[+]Step3: createGroundTruth Start...')
    createGroundTruth(cmdstrings, step3)
    logging.info('[-]Step3 Finished!')
    logging.info('[+]Step4: addGroundTruth Start...')
    addGroundTruth(cmdstrings, step4)
    logging.info('[-]Step4 Finished!')
    '''
    logging.info('[+]Step5: extractFeatures Start...')
    judge = raw_input('[+]Overwrite or not? y/Y for yes and n/N for no: ')
    extractFeatures(cmdstrings, step5, judge)
    logging.info('[-]Step5 Finished!')

    logging.info('[+]Step6: exportRawData Start...')
    csv_name = exportRawData(cmdstrings, step6)
    logging.info('[-]Step6 Finished!')

    logging.info('[+]Start QuincyLearn process......')
    QLearn(csv_name)
    # After function QLearn, the developer must get its own model ,so we could give them some tips about that!
    # generate model
    logging.info('[-]Exit Developer Mode...')


def Forensic_User_Mode():
    '''
    This is the complete process of the forensic user mode
    Users just are supposed to input the name of dump file then wait for the scan result...
    :return:
    '''
    dump_name = raw_input('[+]Please input the name of the dump file you got: ')
    # We could provide the users with some inter models
    custom_model = raw_input('[+]Please input the name of our model: ')
    profile = raw_input('[+]Please input the version of this dump file: ')
    QScan(dump_name, custom_model, profile)
    logging.info('[-]Exit Forensic User Mode...')


def main():
    '''
    Complete auto-execution process
    :return:
    '''
    set_up_logging(0)
    choose = raw_input("Please choose the mode: 1 for developer mode and 2 for forensic user mode: ")
    logging.info(choose)

    if choose == "1":
        start = time.clock()
        Developer_Mode()
        elpased = (time.clock() - start)
        logging.info('Time used in Developer_Mode: ' + str(elpased))
    elif choose == "2":
        start = time.clock()
        Forensic_User_Mode()
        elpased = (time.clock() - start)
        logging.info('Time used in Forensic_User_Mode: ' + str(elpased))


if __name__ == "__main__":
    main()
