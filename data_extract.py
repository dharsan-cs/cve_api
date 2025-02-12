from database import cve ,description ,metric ,configuration ,db_synchronisation
import datetime


class Data_Extracter :

    def cve_data(self ,dict1 ):
        set1 = ["id" ,"sourceIdentifier" ,"published" ,"lastModified" ,"vulnStatus"]  
        param = dict.fromkeys( set1 )

        for key_wrd in set1:
            if key_wrd in dict1.keys():
                param[key_wrd] = dict1[key_wrd]
        
        return cve( string_id = param["id"] ,
                    identifier = param["sourceIdentifier"], 
                    published_date = self.fetch_date( param["published"] ), 
                    last_modified_date = self.fetch_date( param["lastModified"] ), 
                    status = param['vulnStatus'] )

    def description_data(self ,dict1 ,cve_id : int ):
        if "descriptions" in dict1.keys(): 
            for dict2 in dict1['descriptions']: 
                if dict2["lang"] == "en":
                    return description(
                        cve_id = cve_id,
                        statement = dict2["value"]
                        )

    def metric_data(self ,dict1 ,cve_id : int ):
        obj_list = [ ]
        
        if "metrics" in dict1.keys() : 
            
            if "cvssMetricV2" in dict1['metrics'] : 
                set1 = [ "baseScore" ,"vectorString" ,"accessVector" ,"accessComplexity" ,"authentication" ,"confidentialityImpact" ,"integrityImpact" ,"availabilityImpact" ,]
                set2 = ["baseSeverity" ,"exploitabilityScore" ,"impactScore"]
                   
                for cvss_dict in dict1['metrics']['cvssMetricV2']:  
                    param = dict.fromkeys( set1 + set2 )   
                
                    if "cvssData" in cvss_dict.keys() : 
                        for key_wrd in set1 : 
                            if key_wrd in cvss_dict['cvssData'].keys() :
                                param[key_wrd] = cvss_dict['cvssData'][key_wrd]
                    
                    for key_wrd in set2: 
                        if key_wrd in cvss_dict.keys() :
                            param[key_wrd] = cvss_dict[key_wrd]

                    obj_list.append( 
                        metric( 
                        cve_id = cve_id , 
                        severity = param["baseSeverity"],
                        score =  param["baseScore"],
                        vector_string = param["vectorString"], 
                        access_vector = param["accessVector"] ,
                        access_complexity = param["accessComplexity"],
                        authentication = param["authentication"], 
                        confidentiality_impact = param["confidentialityImpact"], 
                        intergrity_impact = param["integrityImpact"],
                        availablity_impact = param["availabilityImpact"],
                        exploitability_score = param["exploitabilityScore"],
                        impact_score = param["impactScore"] , 
                       )
                    )
        
        return obj_list
        
    def config_data(self ,dict1 ,cve_id : int ): 
        config_obj_list = [ ]
        if "configurations" in dict1.keys():
            for dict2 in dict1['configurations']: 
                
                if "nodes" in dict2.keys() : 
                    for dict3 in dict2["nodes"] : 
                        
                        if "cpeMatch" in dict3.keys(): 
                            cpeMatch = dict3["cpeMatch"]
                            
                            for i in range(len(cpeMatch)):
                                config_obj_list.append( 
                                    configuration(
                                        cve_id = cve_id , 
                                        criteria = cpeMatch[i]["criteria"],
                                        match_criteria = cpeMatch[i]["matchCriteriaId"],
                                        vulnerable = cpeMatch[i]["vulnerable"], 
                                ) 
                            )
        return config_obj_list

    def fetch_date(self ,date_time):
        if date_time : 
            return datetime.datetime.strptime(date_time, "%Y-%m-%dT%H:%M:%S.%f").date()
        