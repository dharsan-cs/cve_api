from sqlalchemy import create_engine
from sqlalchemy import Column, Integer, String ,Date ,ForeignKey ,Float
from sqlalchemy.orm import declarative_base
from credentials import user ,password ,db_name

## initailising db engine # URL-encoded '@' as '%40'
engine = create_engine(f"mysql+pymysql://{user}:{password}@localhost/{db_name}")
Base = declarative_base()


class cve( Base ): 
    __tablename__ = "cve"
    id = Column( Integer, primary_key=True ,autoincrement=True)
    string_id = Column( String(255) ,nullable = False )
    identifier = Column( String(255))
    published_date = Column( Date)
    last_modified_date = Column( Date)
    status = Column( String(255))

class description( Base ):
    __tablename__ = "description"
    id = Column( Integer, primary_key=True ,autoincrement=True)
    cve_id = Column( Integer ,ForeignKey('cve.id'))
    statement = Column( String(1000))

class metric( Base ): 
    __tablename__ = "metric"
    id = Column( Integer, primary_key=True ,autoincrement=True) 
    cve_id = Column( Integer ,ForeignKey('cve.id'))
    severity = Column( String(255))
    score = Column( Float)
    vector_string = Column( String(255))
    access_vector = Column( String(255))
    access_complexity = Column( String(255))
    authentication = Column( String(255))
    confidentiality_impact = Column( String(255))
    intergrity_impact = Column( String(255))
    availablity_impact = Column( String(255))
    exploitability_score = Column( Float)
    impact_score = Column( Float)

class configuration( Base ):
    __tablename__ = "configuration" 
    id = Column( Integer, primary_key=True ,autoincrement=True) 
    cve_id = Column( Integer ,ForeignKey('cve.id'))
    criteria = Column( String(255))
    match_criteria = Column( String(255))
    vulnerable = Column( String(255))

class db_synchronisation( Base ): 
    __tablename__ = "db_synchronisation" 
    id = Column( Integer, primary_key=True ,autoincrement=True)
    start_ind = Column( Integer)
    end_ind = Column( Integer)
    date = Column( Date)


if __name__ == "__main__": 
    inp = input( "start_creating_tables(y/n) : ")
    if inp == "y" : 
        try:
            Base.metadata.create_all( engine )
            print( "Tables created succesfully")
        except Exception as e:
            print(f"db_creation : error occurred: {e}")

    



