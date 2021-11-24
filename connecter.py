from flask import Flask, send_from_directory
from flask_restx import Api
import configparser
from predict import predict

app = Flask(__name__)

api = Api(app,
          version='0.0.1',
          title="API",
          description="001")

api.add_namespace(predict, '/app')


@app.route('/<case_id>/<file_name>')
def download_file(case_id: str, file_name: str):
    return send_from_directory('./static/' + case_id,
                               file_name, as_attachment=True)


if __name__ == "__main__":
    parser = configparser.ConfigParser()
    parser.read('connecter.conf')
    app.run(debug=True, host=parser.get('api', 'localIp'), port=parser.get('api', 'port'))
