import os
from app import socketio
from app import createApp
from app.shared import initialize_shared

app = createApp()

if __name__ == '__main__':
    os.environ['TMPDIR'] = '/tmp'
    initialize_shared()

    socketio.run(app, host='0.0.0.0', port=4000)