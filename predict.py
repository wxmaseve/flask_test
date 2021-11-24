from flask import request, jsonify
from flask_restx import Resource, Namespace, fields
import configparser
import requests
import os
import re
import json
import time
import logging.handlers
import shutil
from requests_file import FileAdapter
from exception import InvalidUsage
from werkzeug.exceptions import BadRequest
from threading import Thread
from dbconfig import MysqlController

predict = Namespace('predict')

parser = configparser.ConfigParser()
parser.read('connecter.conf')

UPLOAD_FOLDER = '/pacs/dicomLink/output/'
ALLOWED_EXTENSIONS = {'png', 'dcm', 'json'}


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


def log_setup(logger_name: str):
    logger = logging.getLogger(logger_name)

    # Check handler exists
    if len(logger.handlers) > 0:
        return logger  # Logger already exists

    current_dir = os.path.dirname(os.path.realpath(__file__))
    log_dir = '{}/logs/'.format(current_dir)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # current_file = os.path.basename(__file__)
    # current_file_name = current_file[:-3]  # xxxx.py
    # LOG_FILENAME = log_dir + 'airuntime-{}.log'.format(current_file_name)
    LOG_FILENAME = log_dir + '{}.log'.format(logger_name)

    logger.setLevel(level=logging.DEBUG)

    formatter = logging.Formatter('[%(asctime)s][%(levelname)s|%(filename)s:%(lineno)s][%(threadName)s] >> %(message)s')

    streamHandler = logging.StreamHandler()
    fileHandler = logging.handlers.TimedRotatingFileHandler(filename=LOG_FILENAME,
                                                            when='midnight', interval=1, encoding='utf-8')
    fileHandler.suffix = '%Y%m%d'

    streamHandler.setFormatter(formatter)
    fileHandler.setFormatter(formatter)

    logger.addHandler(streamHandler)
    logger.addHandler(fileHandler)

    return logger


logger = log_setup("airuntime-connecter")


def set_proc_info(process_uuid: str, host_url: str, count: int, uris: str, state: str):
    req = MysqlController()
    myDicom = req.createReq(process_uuid, host_url, count, uris, state)


def get_proc_info(process_uuid: str):
    req = MysqlController()
    myDicom = req.getReq(process_uuid)

    return myDicom


def update_proc_state(process_uuid: str, new_state: str):
    req = MysqlController()
    myDicom = req.getReq(process_uuid)

    if not myDicom:
        return False

    req.updateState(process_uuid, new_state)
    return True


@predict.route('/getState')
@predict.doc(params={'processUUID': 'UUID of this process'})
class GetState(Resource):
    def get(self):
        process_uuid = request.args.get('processUUID')

        if not process_uuid:
            raise BadRequest('processUUID is null.')

        myDicom = get_proc_info(process_uuid)

        if not myDicom:
            return jsonify({'processUUID': process_uuid, 'state': 'IDLE'})

        return jsonify({'processUUID': process_uuid, 'state': myDicom['STATE']})


setState_fields = predict.model('setState', {'processUUID': fields.String, 'newState': fields.String})


@predict.route('/setState')
@predict.doc(body=setState_fields)
class SetState(Resource):
    def post(self):
        process_uuid = request.json.get('processUUID')
        new_state = request.json.get('newState')

        check = get_proc_info(process_uuid)

        if not check:
            return jsonify({'processUUID': process_uuid, 'errMsg': 'this processUUID not exists.'})

        if new_state == 'CANCELED' and check['STATE'] != 'IDLE':
            return jsonify({'processUUID': process_uuid, 'errMsg': 'in progressing or completed.'})

        res = update_proc_state(process_uuid, new_state)

        if res:
            return jsonify({'processUUID': process_uuid, 'result': True})

        return jsonify({'processUUID': process_uuid, 'result': False})


def inference_service(process_uuid: str):
    logger.info("inference_service start! : {}".format(process_uuid))

    procInfo = get_proc_info(process_uuid)

    procInfo['inputPath'] = parser.get('files', 'inputPath') + procInfo['PROCESS_UUID'] + '/'
    procInfo['outputPath'] = parser.get('files', 'outputPath') + procInfo['PROCESS_UUID'] + '/'
    procInfo['inBackupPath'] = parser.get('files', 'backupPath') + 'IN-' + procInfo['PROCESS_UUID']
    procInfo['outBackupPath'] = parser.get('files', 'backupPath') + 'OUT-' + procInfo['PROCESS_UUID'] + '/'
    procInfo['workPath'] = parser.get('files', 'backupPath') + procInfo['PROCESS_UUID'] + '/'
    procInfo['extension'] = parser.get('files', 'extension')
    procInfo['pvcPath'] = parser.get('files', 'pvcPath') + procInfo['PROCESS_UUID'] + '/'

    #logger.debug(procInfo)

    fileList = os.listdir(procInfo['inputPath'])
    imgFileList = [file for file in fileList if file.lower().endswith(procInfo['extension'])]

    logger.info('processUUID: ' + procInfo['PROCESS_UUID'])
    logger.info('input_path: ' + procInfo['inputPath'])
    logger.info('input_backup_path: ' + procInfo['inBackupPath'])
    logger.info('output_path: ' + procInfo['outputPath'])
    logger.info('output_backup_path: ' + procInfo['outBackupPath'])
    logger.info('work_path: ' + procInfo['workPath'])
    logger.info('file_count: [' + str(len(imgFileList)) + ']')
    logger.info('file_list: ' + format(imgFileList))

    headers = {'Content-Type': 'application/json'}
    data = {'accessKey': parser.get('api', 'accessKey')}
    url = parser.get('api', 'issueToken')

    logger.info('[ issueToken ]')
    logger.info('url : ' + json.dumps(url))
    logger.info('headers : ' + json.dumps(headers))
    logger.info('data : ' + json.dumps(data))

    response = requests.post(url, headers=headers, data=json.dumps(data))

    token = ''
    if response is not None:
        if response.status_code == 200:
            if response.json()['code'] == 1:
                token = response.json()['token']
                logger.info(response.json())
                logger.info('token : ' + token)
            else:
                logger.error(response.json())
                return
        else:
            logger.error(response.status_code)
            return

        logger.info(response.json())

    svrIp = parser.get('ftp', 'ip')
    svrId = parser.get('ftp', 'id')
    svrPw = parser.get('ftp', 'pw')

    headers = {'Content-Type': 'application/json', 'Authorization': token,
               'ifServiceId': parser.get('api', 'inferenceId')}

    data = {'ftp_server': svrIp, 'ftp_id': svrId, 'ftp_pw': svrPw, 'study_uid': procInfo['PROCESS_UUID'],
            'input_data_path': procInfo['pvcPath'], 'work_data_path': procInfo['workPath'],
            'output_data_path': procInfo['outputPath'], 'backup_data_path': procInfo['outBackupPath']}
    url = parser.get('api', 'predict')

    logger.info('[ predict ]')
    logger.info('url : ' + json.dumps(url))
    logger.info('headers : ' + json.dumps(headers))
    logger.info('data : ' + json.dumps(data))

    try:
        response = requests.post(url, headers=headers, data=json.dumps(data))

        if response is not None:
            if response.status_code != 200:
                logger.error('status code : ' + str(response.status_code))
                return

            logger.info(response.text)

    except requests.RequestException as e:
        msg = str(e)
        logger.error(msg)
        return
        # raise OpCourierQuayCommunicationError(msg)

    # except ?? as e:
    #   logger.error(e)

    headers = {'Content-Type': 'application/json', 'Authorization': token}
    url = parser.get('api', 'cancellationToken')

    logger.info('[ cancellationToken ]')
    logger.info('url : ' + json.dumps(url))
    logger.info('headers : ' + json.dumps(headers))

    try:
        response = requests.delete(url, headers=headers)

        if response is not None:
            if response.status_code != 200:
                logger.error('status code : ' + str(response.status_code))
                return

            logger.info(response.json())

    except requests.RequestException as e:
        msg = str(e)
        logger.error(msg)
        return

    outFileList = []
    jsonFileList = []
    for i in range(0, 50):
        if os.path.exists(procInfo['outputPath']):
            resultList = os.listdir(procInfo['outputPath'])
            outFileList = [file for file in resultList if file.lower().endswith(procInfo['extension'])]
            jsonFileList = [file for file in resultList if file.lower().endswith("json")]
        time.sleep(10)
        i += 1
        logger.debug("waiting......[" + str(i) + '][' + procInfo['PROCESS_UUID'] + ']')
        # logger.debug("imgFileList")
        # logger.debug(imgFileList)
        # logger.debug("outFileList")
        # logger.debug(outFileList)
        # logger.debug("jsonFileList")
        # logger.debug(jsonFileList)
        logger.debug("input count:[" + str(len(imgFileList)) + "], output count:[" + str(len(outFileList)) + "]")

        if str(len(imgFileList)) == str(len(outFileList)):
            if os.path.exists('./static/'+procInfo['PROCESS_UUID']):
                logger.info("static path already exists.")
                shutil.rmtree('./static/'+procInfo['PROCESS_UUID'])

            shutil.move(procInfo['outputPath'], './static/')
            break

    if str(len(imgFileList)) != str(len(outFileList)):
        return jsonify({'msg': 'timeout'})

    result_json_path = './static/' + procInfo['PROCESS_UUID'] + '/' + procInfo['PROCESS_UUID'] + '.json'
    logger.info("result_json_path : {}".format(result_json_path))

    with open(result_json_path) as json_file:
        json_data = json.load(json_file)
        logger.info("==========================================")
        logger.info(json_data)

    if os.path.exists(procInfo['inBackupPath']):
        logger.info("static path already exists.")
        shutil.rmtree(procInfo['inBackupPath'])

    logger.info('[ move input files ]')
    shutil.move(procInfo['inputPath'], procInfo['inBackupPath'])

    descriptors = []
    for i in outFileList:
        url = 'http://{}:{}/{}/{}'.format(parser.get('api', 'localUrl'), parser.get('api', 'port'),
                                          procInfo['PROCESS_UUID'], i)
        description = {
            "uri": url,
            "mimeType": "application/dicom"  # MIME Type of result SC file
            # "classUID": "...",
            # "transferSyntaxUID": "..."
        }
        descriptors.append(description)

    res = update_proc_state(process_uuid, 'COMPLETED')

    if not res:
        logger.error("updateState error")
        return

    notify_state_changed(procInfo['HOST_URL'], process_uuid, 'COMPLETED')

    # for x in reqList:
    #     for key, value in x.items():
    #         if value == procInfo['processUUID']:
    #             x['state'] = 'COMPLETED'
    #             notifyStateChanged(procInfo['processUUID'], x['state'])

    #######################


    headers = {'Content-Type': 'application/json'}
    data = {
        "processUUID": procInfo['PROCESS_UUID'],
        "report": {
            "finding": str(json_data['Findings'])[1:-1].replace("'", "")
        }
    }
    url = procInfo['HOST_URL'] + parser.get('api', 'report')

    logger.info('[ plugin/report ]')
    logger.info('url : ' + json.dumps(url))
    logger.info('headers : ' + json.dumps(headers))
    logger.info('data : ' + json.dumps(data))

    try:
        response = requests.post(url, headers=headers, data=json.dumps(data))

        if response is not None:
            if response.status_code != 200:
                logger.error('status code : ' + str(response.status_code))
                # logger.error(response.text)
                # return jsonify({'error code': str(response.status_code), 'msg': response.text})

            # logger.info(response.text)

    except requests.RequestException as e:
        msg = str(e)
        logger.error(msg)
        # return

    headers = {'Content-Type': 'application/json'}
    data = {
        "processUUID": procInfo['PROCESS_UUID'],
        "isLesion": (True if json_data['Findings']['Result'] else False),
        "lesionName": json_data['Findings']['Name'],
        "score": json_data['Findings']['Score'],
        "severity": json_data['Findings']['Severity']
        #"lesionLocation": json_data['Findings']['Result']
    }
    url = procInfo['HOST_URL'] + parser.get('api', 'result')

    logger.info('[ /notifyDetailResult ]')
    logger.info('url : ' + json.dumps(url))
    logger.info('headers : ' + json.dumps(headers))
    logger.info('data : ' + json.dumps(data))

    try:
        response = requests.post(url, headers=headers, data=json.dumps(data))

        if response is not None:
            if response.status_code != 200:
                logger.error('status code : ' + str(response.status_code))
                # logger.error(response.text)
                # return jsonify({'error code': str(response.status_code), 'msg': response.text})

            # logger.info(response.text)

    except requests.RequestException as e:
        msg = str(e)
        logger.error(msg)
        # return

    headers = {'Content-Type': 'application/json'}
    data = {
        "applicationID": "BrainCTReportAI",
        "processUUID": procInfo['PROCESS_UUID'],
        # "caseID": procInfo["CASE_ID"],  # 특정 case에 배정된 ID
        "descriptors": descriptors
    }
    url = procInfo['HOST_URL'] + parser.get('api', 'notifyDataAvailable')

    logger.info('[ notifyDataAvailable ]')
    logger.info('url : ' + json.dumps(url))
    logger.info('headers : ' + json.dumps(headers))
    logger.info('data : ' + json.dumps(data))

    try:
        response = requests.post(url, headers=headers, data=json.dumps(data))

        if response is not None:
            if response.status_code != 200:
                logger.error('status code : ' + str(response.status_code))
                # logger.error(response.text)
                # return jsonify({'error code': str(response.status_code), 'msg': response.text})

            #logger.info(response.text)

    except requests.RequestException as e:
        msg = str(e)
        logger.error(msg)
        # return


    logger.info('==============threaded_finish=================')


def get_url_contents(url: str):
    s = None
    try:
        s = requests.Session()
        if url.lower().startswith('file://'):
            s.mount('file://', FileAdapter())
            resp = s.get(url)
        else:
            resp = s.get(url)
        return resp
    finally:
        if s is not None:
            s.close()


launch_fields = predict.model('launch', {'processUUID': fields.String,
                                         'hostURL': fields.String,
                                         'uris': fields.List(fields.String)})


@predict.route('/launch')
@predict.doc(body=launch_fields)
class Launch(Resource):

    def post(self):

        check = get_proc_info(request.json.get('processUUID'))

        if check:
            return jsonify({'processUUID': request.json.get('processUUID'), 'errMsg': 'this processUUID already requested.'})

        # ============================================================== process info
        procInfo = {}
        procInfo['PROCESS_UUID'] = request.json.get('processUUID')
        procInfo['HOST_URL'] = request.json.get('hostURL')
        procInfo['URIS'] = request.json.get('uris')
        procInfo['STATE'] = 'IDLE'

        set_proc_info(procInfo['PROCESS_UUID'], procInfo['HOST_URL'], len(procInfo['URIS']), str(procInfo['URIS']), procInfo['STATE'])

        procInfo['inputPath'] = parser.get('files', 'inputPath') + procInfo["PROCESS_UUID"] + '/'
        procInfo['outputPath'] = parser.get('files', 'outputPath') + procInfo["PROCESS_UUID"] + '/'
        procInfo['inBackupPath'] = parser.get('files', 'backupPath') + 'IN-' + procInfo["PROCESS_UUID"]
        procInfo['outBackupPath'] = parser.get('files', 'backupPath') + 'OUT-' + procInfo["PROCESS_UUID"] + '/'
        procInfo['workPath'] = parser.get('files', 'backupPath') + procInfo["PROCESS_UUID"] + '/'
        procInfo['extension'] = parser.get('files', 'extension')
        procInfo['pvcPath'] = parser.get('files', 'pvcPath') + procInfo["PROCESS_UUID"] + '/'

        logger.info('PROCESS_UUID: ' + procInfo['PROCESS_UUID'])
        logger.info('HOST_URL: ' + procInfo['HOST_URL'])
        logger.info('URIS: ' + str(procInfo['URIS']))

        # ============================================================== mkdir
        if os.path.exists(procInfo['inputPath']):
            logger.info("inputPath already exists.")
            shutil.rmtree(procInfo['inputPath'])

        os.makedirs(procInfo['inputPath'])
        os.system('chmod -R 777 ' + procInfo['inputPath'])
        logger.info('inputPath: ' + procInfo['inputPath'])

        if os.path.exists(procInfo['workPath']):
            logger.info("workPath already exists.")
            shutil.rmtree(procInfo['workPath'])

        os.makedirs(procInfo['workPath'])
        os.system('chmod -R 777 ' + procInfo['workPath'])  # permission for custom model
        logger.info('workPath: ' + procInfo['workPath'])

        if os.path.exists(procInfo['outBackupPath']):
            logger.info("outBackupPath already exists.")
            shutil.rmtree(procInfo['outBackupPath'])

        os.makedirs(procInfo['outBackupPath'])
        os.system('chmod -R 777 ' + procInfo['outBackupPath'])
        logger.info('outBackupPath: ' + procInfo['outBackupPath'])

        # ============================================================== download dicom file
        for i in range(len(procInfo['URIS'])):
            check = get_proc_info(procInfo['PROCESS_UUID'])
            if check['STATE'] == 'CANCELED':
                logger.info("REQ CANCELED")
                return
            url = procInfo["URIS"][i]
            file = get_url_contents(url)
            filename = re.findall("filename=(.+)", file.headers['Content-Disposition'])[0][1:-2]
            with open(procInfo['inputPath'] + filename, "wb") as f:
                f.write(file.content)
                f.close()

        check = get_proc_info(procInfo['PROCESS_UUID'])
        if check['STATE'] == 'CANCELED':
            logger.info("REQ CANCELED")
            return

        procInfo['STATE'] = 'INPROGRESS'

        update_proc_state(procInfo['PROCESS_UUID'], procInfo['STATE'])
        notify_state_changed(procInfo['HOST_URL'], procInfo['PROCESS_UUID'], procInfo['STATE'])

        thread = Thread(target=inference_service, args=(procInfo['PROCESS_UUID'],))
        thread.daemon = True
        thread.start()

        return jsonify({'processUUID': procInfo['PROCESS_UUID'], 'state': procInfo['STATE']})


def notify_state_changed(host_url: str, process_uuid: str, state: str):
    headers = {'Content-Type': 'application/json'}
    data = {'processUUID': process_uuid, 'state': state}
    url = host_url + parser.get('api', 'notifyStateChanged')

    logger.info('[ notifyStateChanged ]')
    logger.info('url : ' + json.dumps(url))
    logger.info('headers : ' + json.dumps(headers))
    logger.info('data : ' + json.dumps(data))

    try:
        response = requests.post(url, headers=headers, data=json.dumps(data))

        if response is not None:
            if response.status_code != 200:
                logger.error('status code : ' + str(response.status_code))
                logger.error('msg : ' + response.text)
                return False

            logger.info(response.text)

    except requests.RequestException as e:
        msg = str(e)
        logger.error(msg)
        return False

    return True


@predict.errorhandler(InvalidUsage)
def handle_invalid_usage(error):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response
