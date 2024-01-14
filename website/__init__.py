from flask import Flask
from flask_pymongo import PyMongo
import mongoengine

mongo2=PyMongo()

def create_app():
    app=Flask(__name__)
    app.config['SECRET_KEY']='poiuytrewqlkjhgf'
    app.config['MONGO_URI'] = 'mongodb://localhost:27017/QandA'

    mongoengine.connect(host=app.config['MONGO_URI'])

    mongo2.init_app(app)

    
    from .auth import auth


    app.register_blueprint(auth,url_prefix='/')

    from json import JSONEncoder
    from bson.objectid import ObjectId

    class CustomJSONEncoder(JSONEncoder):
        def default(self, obj):
            if isinstance(obj, ObjectId):
                return str(obj)
            return super().default(obj)
    
    app.json_encoder = CustomJSONEncoder

    return app




  