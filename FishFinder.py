import FeatureExtractor as FeatureE
import discord
import emoji
import numpy as np
import os
import pandas as pd
import re as regex
from sklearn import preprocessing
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')
ChannelName ="PhishfinderLogs"
#clock yellow orange green red
emojis = [emoji.emojize(':stopwatch:'), emoji.emojize(':yellow_square:'), emoji.emojize(':orange_square:'), emoji.emojize(':green_square:'),emoji.emojize(':red_square:'),emoji.emojize(":cross_mark:")]
features1 = [
    "length_url",
    "nb_eq",
    "nb_underscore",
    "nb_www",
    "http_in_path",
    "ratio_digits_url",
    "ratio_digits_host",
    "port",
    "shortening_service",
    "char_repeat",
    "longest_word_path",
    "phish_hints",
    "domain_in_brand",
    "suspecious_tld",
    "nb_hyperlinks",
    "ratio_intHyperlinks",
    "ratio_extRedirection",
    "safe_anchor",
    "right_clic",
    "empty_title",
    "domain_in_title",
    "domain_with_copyright",
    "domain_registration_length",
    "domain_age",
    "web_traffic",
    "dns_record",
    "google_index",
    "page_rank",
    "status",
]

features2 = [
    "length_hostname",
    "nb_dots",
    "nb_hyphens",
    "nb_qm",
    "nb_underscore",
    "nb_space",
    "nb_www",
    "ratio_digits_host",
    "length_words_raw",
    "longest_word_path",
    "avg_words_raw",
    "phish_hints",
    "nb_hyperlinks",
    "google_index",
    "page_rank",
    "status",
]

features3 = [
'length_url', 
'length_hostname', 
'ip', 
'nb_qm', 
'nb_eq', 
'nb_slash', 
'nb_www', 
'ratio_digits_url', 
'phish_hints', 
'nb_hyperlinks', 
'ratio_intHyperlinks', 
'domain_in_title', 
'domain_age', 
'google_index', 
'page_rank',
'status',
]

features4 = [
    "length_hostname",
    "ip",
    "nb_hyphens",
    "nb_qm",
    "nb_underscore",
    "nb_space",
    "nb_www",
    "shortening_service",
    "avg_words_raw",
    "avg_word_path",
    "phish_hints",
    "nb_hyperlinks",
    "ratio_extHyperlinks",
    "ratio_extRedirection",
    "ratio_intMedia",
    "ratio_extMedia",
    "safe_anchor",
    "domain_age",
    "google_index",
    "page_rank",
    "status",
]
featurestoget = [
'length_url',
'length_hostname',
'ip',
'nb_dots',
'nb_hyphens',
'nb_qm',
'nb_eq',
'nb_underscore',
'nb_slash',
'nb_space',
'nb_www',
'http_in_path',
'ratio_digits_url',
'ratio_digits_host',
'port',
'shortening_service',
'char_repeat',
'longest_word_path',
'length_words_raw',
'avg_words_raw',
'avg_word_path',
'phish_hints',
'domain_in_brand',
'suspecious_tld',
'nb_hyperlinks',
'ratio_extHyperlinks',
'ratio_intHyperlinks',
'ratio_extRedirection',
'ratio_intMedia',
'ratio_extMedia',
'safe_anchor',
'right_clic',
'empty_title',
'domain_in_title',
'domain_with_copyright',
'domain_registration_length',
'domain_age',
'web_traffic',
'dns_record',
'google_index',
'page_rank',
]




pd.set_option('display.max_column', None)
pd.set_option('display.max_rows', None)
pd.set_option('display.max_seq_items', None)
pd.set_option('display.max_colwidth', 500)
pd.set_option('expand_frame_repr', True)
dataBaseline = pd.read_csv("PathToDataset")
#features = dataBaseline.drop("status", 1).columns.values.tolist()
###d = {'legitimate': 1, 'phishing': 0}
###data['status'] = data['status'].map(d)
#normaldata = dataBaseline[features].copy()
#dataBaseline = dataBaseline.drop(features, 1)
#x = normaldata.values #returns a numpy array 
#min_max_scaler = preprocessing.MinMaxScaler(feature_range=(0, 10))
#x_scaled = min_max_scaler.fit_transform(x)
#normaldata = pd.DataFrame(x_scaled, columns=normaldata.columns)
#dataBaseline = pd.concat([normaldata, dataBaseline], axis=1)


dataset1 = dataBaseline[features1].copy()
dataset2 = dataBaseline[features2].copy()
dataset3 = dataBaseline[features3].copy()
dataset4 = dataBaseline[features4].copy()

temp = dataset1
X = temp.drop("status", 1)
featuretodrop1 = X.columns.values.tolist()
y = dataset1.drop(featuretodrop1, 1)
Xdataset1_train, Xdataset1_test, ydataset1_train, ydataset1_test = train_test_split(X, y, test_size=.95, random_state=42)

temp = dataset2
X = temp.drop("status", 1)
featuretodrop2 = X.columns.values.tolist()
y = dataset2.drop(featuretodrop2, 1)
Xdataset2_train, Xdataset2_test, ydataset2_train, ydataset2_test = train_test_split(X, y, test_size=.95, random_state=42)

temp = dataset3
X = temp.drop("status", 1)
featuretodrop3 = X.columns.values.tolist()
y = dataset3.drop(featuretodrop3, 1)
Xdataset3_train, Xdataset3_test, ydataset3_train, ydataset3_test = train_test_split(X, y, test_size=.95, random_state=42)

temp = dataset4
X = temp.drop("status", 1)
featuretodrop4 = X.columns.values.tolist()
y = dataset4.drop(featuretodrop4, 1)
Xdataset4_train, Xdataset4_test, ydataset4_train, ydataset4_test = train_test_split(X, y, test_size=.95, random_state=42)

def runRandomForest(Xtrain, ytrain):
        
    pipe = Pipeline([("scale", StandardScaler()),
                    ("rf", RandomForestClassifier())
                    ])

    param_grid = {}
    grid = GridSearchCV(pipe, param_grid, cv=10, n_jobs=-1)
    grid.fit(Xtrain, ytrain.values.ravel())

    model_best = grid.best_estimator_
    model_best.fit(Xtrain, ytrain.values.ravel())

    return model_best

def runExtraTrees(Xtrain, ytrain):
    
    pipe = Pipeline([("scale", StandardScaler()),
                    ("etc", ExtraTreesClassifier())
                    ])

    param_grid = {}
    
    grid = GridSearchCV(pipe, param_grid, cv=10, n_jobs=-1)
    grid.fit(Xtrain, ytrain.values.ravel())

    model_best = grid.best_estimator_
    model_best.fit(Xtrain, ytrain.values.ravel())
    
    return model_best
    
Algo1 = runRandomForest(Xdataset1_train, ydataset1_train)
Algo2 = runExtraTrees(Xdataset2_train, ydataset2_train)
Algo3 = runRandomForest(Xdataset3_train, ydataset3_train)
Algo4 = runRandomForest(Xdataset4_train, ydataset4_train)

TOKEN = "Discord API Token"
client = discord.Client()

def normalizeDataExt(data):
    """"""
    #d = {'legitimate': 1, 'phishing': 0}
    #data['status'] = data['status'].map(d)
    normaldata = data[featurestoget].copy()
    x = normaldata.values #returns a numpy array
    min_max_scaler = preprocessing.MinMaxScaler( feature_range=(0, 10))
    x_scaled = min_max_scaler.fit_transform(x)
    normaldata = pd.DataFrame(x_scaled,columns=normaldata.columns)


   
    return  normaldata

def check_results(answer1,answer2,answer3,answer4):
    
    i=0
    if (answer1[0] == 'phishing'):
        i = i+1
    if (answer2[0] == 'phishing'):
        i = i+1
    if (answer3[0] == 'phishing'):
        i = i+1
    if (answer4[0] == 'phishing'):
        i = i+1
        
    return i

@client.event
async def on_ready():
    print(f'{client.user} has connected to Discord!')


@client.event
async def on_message(message):
    urls = regex.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*(),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', message.content.lower())
    flag = False
    flagforNetworkIssue = False
    ##Check if the log channel is there:
    Guild = message.guild
    textchannelList = Guild.text_channels
    flagChannel = True
    for x in textchannelList:
        if(x.name == ChannelName.lower()):
            flagChannel = False
    if(flagChannel):
         await Guild.create_text_channel(ChannelName)
    if(len(urls) > 0):
        flag = True
    if (flag == True):
        await message.add_reaction(emojis[0])
        print(urls[0])
        urlinquestion = pd.DataFrame(FeatureE.extract_features(urls[0]), columns=featurestoget)
#        urlinquestion = normalizeDataExt(urlinquestion)
        if urlinquestion.shape == (0,41):
            flagforNetworkIssue = True
        embedVar  = ""
        Channel = discord.utils.get(Guild.channels, name=ChannelName.lower())
        await message.remove_reaction(emojis[0],client.user)
        if flagforNetworkIssue == False:    
            awns1 = Algo1.predict(urlinquestion[featuretodrop1].copy())
            awns2 = Algo2.predict(urlinquestion[featuretodrop2].copy())
            awns3 = Algo3.predict(urlinquestion[featuretodrop3].copy())
            awns4 = Algo4.predict(urlinquestion[featuretodrop4].copy())
            number = check_results(awns1,awns2,awns3,awns4)
            
            embedVar  = ""
            print(awns1[0])
            print(awns2[0])
            print(awns3[0])
            print(awns4[0])
        if flagforNetworkIssue == True: 
            number =5
        if(number ==0 ):
            embedVar = discord.Embed(title='Results On '+urls[0].replace("http://","").replace("https://",""), color=0x00FF00, description='Even though the algorithm returned legitimate please use caution', type='rich')
            embedVar.add_field(name="Algorithm 1:", value=awns1[0], inline=False)
            embedVar.add_field(name="Algorithm 2:", value=awns2[0], inline=False)
            embedVar.add_field(name="Algorithm 3:", value=awns3[0], inline=False)
            embedVar.add_field(name="Algorithm 4:", value=awns4[0], inline=False)
            await message.add_reaction(emojis[3])
        if(number == 1):
            embedVar = discord.Embed(title='Results On '+urls[0].replace("http://","").replace("https://",""),description='The algorithm detected some phishing please use extreme caution', color=0xFFFF00, type='rich')
            embedVar.add_field(name="Algorithm 1:", value=awns1[0], inline=False)
            embedVar.add_field(name="Algorithm 2:", value=awns2[0], inline=False)
            embedVar.add_field(name="Algorithm 3:", value=awns3[0], inline=False)
            embedVar.add_field(name="Algorithm 4:", value=awns4[0], inline=False)
            await message.add_reaction(emojis[1])
        if(number == 2):
            embedVar = discord.Embed(title='Results On '+urls[0].replace("http://","").replace("https://",""),description='The algorithm detected some phishing please use extreme caution', color=0xFF9900, type='rich')
            embedVar.add_field(name="Algorithm 1:", value=awns1[0], inline=False)
            embedVar.add_field(name="Algorithm 2:", value=awns2[0], inline=False)
            embedVar.add_field(name="Algorithm 3:", value=awns3[0], inline=False)
            embedVar.add_field(name="Algorithm 4:", value=awns4[0], inline=False)
            await message.add_reaction(emojis[2])
        if(number == 3):
            embedVar = discord.Embed(title='Results On '+urls[0].replace("http://","").replace("https://",""),description='The algorithm detected some phishing please use extreme caution', color=0xFF0000, type='rich')
            embedVar.add_field(name="Algorithm 1:", value=awns1[0], inline=False)
            embedVar.add_field(name="Algorithm 2:", value=awns2[0], inline=False)
            embedVar.add_field(name="Algorithm 3:", value=awns3[0], inline=False)
            embedVar.add_field(name="Algorithm 4:", value=awns4[0], inline=False)
            await message.add_reaction(emojis[4])
        if(number == 4):
            embedVar = discord.Embed(title='Results On '+urls[0].replace("http://","").replace("https://",""), description='This URL was removed as it was detected as 100% phishing if you feel this is a mistake please contact a admin.',color=0x000000, type='rich')
            embedVar.add_field(name="Algorithm 1:", value=awns1[0], inline=False)
            embedVar.add_field(name="Algorithm 2:", value=awns2[0], inline=False)
            embedVar.add_field(name="Algorithm 3:", value=awns3[0], inline=False)
            embedVar.add_field(name="Algorithm 4:", value=awns4[0], inline=False)
            await message.delete()  # Delete the message
        if(number == 5):
            embedVar = discord.Embed(title='Error was unable to access '+urls[0].replace("http://","").replace("https://",""),description='Please proceed with extra caution when looking at this link', color=0x660000, type='rich')
            
            await message.add_reaction(emojis[5])

        await Channel.send(embed=embedVar)
        #await Channel.send(+ 'Algorithm 1: '+awns1[0]+ '\n'+ 'Algorithm 2: '+awns2[0]+ '\n'+ 'Algorithm 3: '+awns3[0]+ '\n'+ 'Algorithm 4: '+awns4[0])

@client.event
async def on_guild_join(guild):
    flag = True
    textchannelList = guild.text_channels
    for x in textchannelList:
        print(x)
        if(x == ChannelName):
            flag = False
        

    if(flag):
         await guild.create_text_channel(ChannelName)
   

client.run(TOKEN)