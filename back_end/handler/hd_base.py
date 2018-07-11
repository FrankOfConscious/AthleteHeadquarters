from flask import request, make_response
from flask import jsonify
from flask import abort
from app import appAHQ
import functools
import flask

def require(*required_args):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kw):
            for arg in required_args:
                if arg not in request.json:
                    return abort(400)
            return func(*args, **kw)
        return wrapper
    return decorator

@appAHQ.errorhandler(400)
def not_found(error):
     return make_response(flask.jsonify({'error': '参数不正确'}), 400)


