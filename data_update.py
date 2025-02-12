from database import engine ,cve, description, metric, configuration, db_synchronisation
from sqlalchemy.orm import sessionmaker
from data_insert import Data_Insert 
from credentials import base_url 
import requests
import datetime

##creating a session object with db 
Session = sessionmaker(bind=engine)
session = Session()


class Data_Update(Data_Insert): 

    def update_db(self ,last_mod_start ,last_mod_end):
        params = {  "lastModStartDate": last_mod_start ,"lastModEndDate": last_mod_end }
        response = requests.get( base_url ,params = params)
        ind = session.query(cve).count() + 1 
        
        if response.status_code == 200 : 
            data = response.json( )
            vulnerabilities = data['vulnerabilities']
            self.init_empty_list( )

            for i in range( len(vulnerabilities) ):

                if "cve" in vulnerabilities[i].keys():
                    dict1 = vulnerabilities[i]["cve"]                       
                    old_cve_obj = session.query(cve).filter(cve.string_id == dict1['id'] ).first()
                    
                    ## row need to updated
                    if old_cve_obj :
                        self.update_single_cve(dict1 ,old_cve_obj)
                    ## inserting new data 
                    else:
                        self.insert_single_cve(dict1 ,ind)
                        ind = ind + 1 
                
            ## this commits all updations and new rows of the cve table  
            session.add_all(self.cve_list)
            session.commit() 
                
            ## adding new rows of remaining table 
            session.add_all(self.metric_list)
            session.add_all(self.descrip_list)
            session.add_all(self.config_list) 

            ##updating db_synchronisation table
            self.update_sync_table(ind)
 
            ##commiting all the changes 
            session.commit()
        else:
            print( f"Request to nvd api status-code : {response.status_code}")
    
    
    def update_single_cve(self ,dict1 ,old_cve_obj):
        self.update_cve(dict1 ,old_cve_obj)
        self.update_description(dict1 ,old_cve_obj.id)
        self.update_metric(dict1 ,old_cve_obj.id)
        self.update_configuration(dict1 ,old_cve_obj.id)
                            
    def update_cve(self ,dict1 ,old_cve_obj ): 
        old_cve_obj.identifier = dict1["sourceIdentifier"]
        old_cve_obj.published_date = self.fetch_date( dict1["published"] )
        old_cve_obj.last_modified_date = self.fetch_date( dict1["lastModified"] )
        old_cve_obj.status = dict1['vulnStatus']

    def update_description(self ,dict1 ,cve_id ):
        session.query(description).filter(description.cve_id == cve_id ).delete()
        new_descript_obj = self.description_data(dict1 ,cve_id)
        session.commit()
        if new_descript_obj :
            self.descrip_list.append(new_descript_obj) 

    def update_metric(self ,dict1 ,cve_id):
        new_metric_objs = self.metric_data(dict1, cve_id)
        session.query(metric).filter(metric.cve_id == cve_id).delete()
        session.commit()
        if len(new_metric_objs) > 0:
            self.metric_list += new_metric_objs

    def update_configuration(self ,dict1 ,cve_id):
        new_config_objs = self.config_data(dict1 ,cve_id)
        session.query(configuration).filter(configuration.cve_id == cve_id ).delete()
        session.commit()
        if len(new_config_objs) > 0: 
            self.config_list += new_config_objs
    
    def update_sync_table(self ,ind):
        session.query(db_synchronisation).delete()
        obj = db_synchronisation( start_ind = 1 ,end_ind = ind  ,date = datetime.date.today() )
        session.add(obj)

if __name__ == "__main__" :
    inp = input( f"Do you update db (y/n) : ")
    if inp == "y" : 
        try:
            update_obj = Data_Update()
            last_mod_start = input("Enter last_mod_start (yyyy-mm-dd): ") + "T00:00:00.000Z"
            last_mod_end = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            update_obj.update_db(last_mod_start, last_mod_end)
            print("Database up-to-date")
            
        except Exception as e:
            print(f"updation : error occurred: {e}") 