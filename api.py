from database import engine ,cve, description, metric, configuration, db_synchronisation
from data_update import Data_Update ,session
from credentials import update_time_interval
from flask import Flask ,jsonify
import datetime

##variable to kep track of last update date 
LAST_UPDATE_DATE = None
update_obj = None 

##fetch last updation date 
def fetch_last_update_date( ):
    global LAST_UPDATE_DATE
    db_synch_obj = session.query(db_synchronisation).first()
    if db_synch_obj : 
        LAST_UPDATE_DATE = db_synch_obj.date  
    else:
        print( "Last updation date not found")
        exit()

##initalise update oject
def init_update_obj():
    global update_obj 
    update_obj = Data_Update( ) 

##creating flask instance  
app = Flask(__name__)


## checks for timeout and update the db  
def check_for_update():
    current_date = datetime.date.today()
    global LAST_UPDATE_DATE ,update_obj 

    if (current_date - LAST_UPDATE_DATE ).days >= update_time_interval :
        try : 
            update_obj.update_db( 
                last_mod_start = LAST_UPDATE_DATE,
                last_mod_end = current_date ,
            )
            LAST_UPDATE_DATE = current_date 
        except Exception as e:
            print(f"API-Updation/error occurred: {e}") 


##home page route 
@app.route("/<int:start_ind>/<int:result_per_page>")
def cve_page_data(start_ind ,result_per_page):
    
    global cve
    check_for_update() 
    
    data = {
        "start_index": start_ind,
        "results_per_page": result_per_page,
        "total_results": session.query(cve).count(),
        "cve": [],
    }
    
    cve_objs = session.query(cve).filter( cve.id.between(start_ind ,start_ind + result_per_page -1)).all()
    for obj in cve_objs:
        data["cve"].append( { 
            "cve_id" : obj.string_id,
            "identifer" : obj.identifier,
            "published_date" : obj.published_date ,
            "last_modified_date" : obj.last_modified_date,
            "status" : obj.status
        })
    
    return jsonify(data)


##single cve page data
@app.route("/cve/<string:cve_id>")
def cve_specific_data(cve_id):
    
    global cve, description, metric, configuration
    check_for_update()
    
    cve_obj = session.query(cve).filter( cve.string_id == cve_id ).first()
    descrip_obj = session.query(description).filter( description.cve_id == cve_obj.id ).first()
    metric_obj = session.query(metric).filter( metric.cve_id == cve_obj.id ).first()
    config_obj_list = session.query(configuration).filter( configuration.cve_id == cve_obj.id ).all()

    data = { 
        "id" : cve_obj.string_id ,
        "description" : descrip_obj.statement,
        "severity" : metric_obj.severity,
        "score" : metric_obj.score,
        "vector_string" : metric_obj.vector_string,
        "access_vector" : metric_obj.access_vector,
        "access_complexity" : metric_obj.access_complexity,
        "authentication" : metric_obj.authentication,
        "confidentiality_impact" : metric_obj.confidentiality_impact,
        "intergrity_impact" : metric_obj.intergrity_impact,
        "availablity_impact" : metric_obj.availablity_impact,
        "exploitability_score" : metric_obj.exploitability_score,
        "impact_score" : metric_obj.impact_score,
        "cpe" : [ ]
    }

    for obj in config_obj_list : 
        data["cpe"].append( {
            "criteria" : obj.criteria,
            "match_criteria" : obj.match_criteria,
            "vulnerable" : obj.vulnerable
        })
    
    return jsonify(data)


if __name__ == "__main__" : 
    fetch_last_update_date()
    init_update_obj()
    app.run(debug=True)

    
            

