from sqlalchemy.orm import sessionmaker
from data_extract import Data_Extracter
from database import engine ,cve ,db_synchronisation
from credentials import base_url 
import requests
import datetime


##creating a session object with db 
Session = sessionmaker(bind=engine)
session = Session()


class Data_Insert(Data_Extracter):
    max_fetch_per_request = 20
    results_per_page = 10  
    
    ##fetch data from nvd and insert it in local mysql db 
    def fetch_insert_data(self):
        start_index = session.query(cve).count()
        limit = start_index + self.max_fetch_per_request  
        i1 = i2 = start_index + 1
        
        while start_index < limit : 
            param = {"startIndex": start_index , "resultsPerPage": self.results_per_page}
            response = requests.get(base_url ,params = param )
                
            if response.status_code == 200:
                data = response.json( )
                vulnerabilities = data['vulnerabilities']
                self.init_empty_list()

                for i in range( len(vulnerabilities) ):
                    if "cve" in vulnerabilities[i].keys():              
                        dict1 = vulnerabilities[i]["cve"]                      
                        self.insert_single_cve(dict1 ,i2)
                        i2 += 1

                ##first commiting the cve table to prevent foreighn key error  
                session.add_all(self.cve_list)  
                session.commit()
                    
                ##next commiting the other two tables 
                session.add_all(self.descrip_list)
                session.add_all(self.metric_list)
                session.add_all(self.config_list)
                session.commit()

                #incrementing start index 
                start_index = start_index + len(vulnerabilities)

            else:
                print( f"Request to nvd api status-code : {response.status_code}")
                break 
                
        ##keep track of date in which new set of rows added
        self.insert_synch_model( i1 ,i2 )
    
    ## intialise object empty list to keep track of newly added rows  
    def init_empty_list(self):
        self.cve_list = [ ]
        self.descrip_list = [ ] 
        self.metric_list = [ ] 
        self.config_list = [ ]

    ##function is responsible for adding new cve data(cve ,descrip ,metric ,config) to db 
    def insert_single_cve(self ,dict1 ,ind ):
        ##creating db instances 
        new_cve_obj = self.cve_data(dict1)
        new_descript_obj = self.description_data(dict1 ,ind)
        new_metric_objs = self.metric_data(dict1, ind)
        new_config_objs = self.config_data(dict1 ,ind)
        
        ##adding new instance to private lists
        self.cve_list.append(new_cve_obj)
        if new_descript_obj : 
            self.descrip_list.append( new_descript_obj )
        if len(new_metric_objs) > 0 : 
            self.metric_list += new_metric_objs
        if len(new_config_objs) > 0 :
            self.config_list += new_config_objs
    
    ##add new synchronisation row (to keep track of which set of data added at which date)
    def insert_synch_model(self ,i1 ,i2):
        ##stop if insertion is made 
        if i1 == i2 : 
            return 

        current_date = datetime.date.today()
        obj = db_synchronisation( 
            start_ind = i1 ,
            end_ind = i2 ,
            date = current_date,
        )
        session.add(obj)
        session.commit()


if __name__ == "__main__" :
    inp = input( f"Start_fetch_remaining_data limit - {Data_Insert.max_fetch_per_request} (y/n) : ")
    if inp == "y" : 
        try:
            insert_obj = Data_Insert( )
            insert_obj.fetch_insert_data()
            print("Insertion Over")
        except Exception as e:
            print(f"insertion : error occurred: {e}") 
    