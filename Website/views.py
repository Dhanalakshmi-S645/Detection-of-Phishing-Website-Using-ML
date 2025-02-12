from django.shortcuts import render
from django.contrib.auth.models import User,auth
from django.contrib import messages
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from .models import Phishing
from nltk.tokenize import RegexpTokenizer
from nltk.stem.snowball import SnowballStemmer
from wordcloud import WordCloud, STOPWORDS, ImageColorGenerator

from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

import seaborn as sns
import time

from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix
from nltk.tokenize import RegexpTokenizer
from nltk.stem.snowball import SnowballStemmer
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.pipeline import make_pipeline

from PIL import Image
from wordcloud import WordCloud, STOPWORDS, ImageColorGenerator
import pickle
import ml
from sklearn.svm import SVC
import pandas as pd
from sklearn.preprocessing import LabelEncoder
# Create your views here.
def index(request):
    return render(request,"index.html")


def register(request):
    if request.method == 'POST':
        firstName=request.POST.get('firstName')
        lastName=request.POST.get('lastName')
        username=request.POST.get('username')
        email=request.POST.get('email')
        password=request.POST.get('password')
        c_password=request.POST.get('c_password')

        if password == c_password:
            if User.objects.filter(username=username).exists():
                messages.info(request, 'Username is already exist')
                return render(request,'register.html')
            elif User.objects.filter(email=email).exists():
                messages.info(request, 'Email is already exist')
                return render(request,'register.html')
            else:
                #save data in db
                user = User.objects.create_user(first_name=firstName, last_name=lastName, email=email,username=username,password=password)
                user.save()
                print('user created')
                return render(request,'login.html')
        else:
            messages.info(request, 'Invalid Credentials')
            return render(request,'register.html')
            return redirect('/')
    else:
        return render(request, 'register.html')

def login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user =auth.authenticate(username=username, password=password)

        if user is not None:
            print('Authenticated')
            return render(request,'data.html')
        else:
            print('Not authenticated')
            messages.info(request, 'Invalid credentials')
            return render(request,'login.html')
    else:
        return render(request, 'login.html')
"""
def form(request):
    return render(request,"form.html")"""
"""
def predPage(request):
    #SFH	popUpWidnow	SSLfinal_State	Request_URL	URL_of_Anchor	web_traffic	URL_Length	age_of_domain	having_IP_Address

    if request.method == 'POST':
        sfh = int(request.POST['sfh'])
        pop = int(request.POST['pop'])
        ssl = int(request.POST['ssl'])
        anchor=int(request.POST['anchor'])
        url = int(request.POST['url'])
        web = int(request.POST['web'])
        length = int(request.POST['length'])
        domain = int(request.POST['domain'])
        ip = int(request.POST['ip'])


        data = [(sfh,pop,ssl,anchor,url,web,length,domain,ip)]
        print(data)
        #data = [5432, 1234, 120, 360, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0]
        is_eligible = ml.output(data)
        if is_eligible == '0':
            return render(request, 'success.html')
        elif is_eligible=='-1':
            return render(request,"success.html")
        else:
            return render(request, 'failure.html')
    else:
        return render(request, 'form.html')
"""
def logout(request):
    auth.logout(request)
    return render(request,"index.html")

def data(request):
    return render(request,"data.html")
"""
def predict(request):
    if request.method=="POST":
        url=request.POST['url']
        df=pd.read_csv("E:\Phishing\datasets\Phising_Site.csv")
        tokenizer = RegexpTokenizer(r'[A-Za-z]+')
        tokenizer.tokenize(df.URL[0])  # this will fetch all the words from the first URL
        # Tokenizing all the rows
        print('Getting words tokenized ...')
        t0 = time.perf_counter()
        df['text_tokenized'] = df.URL.map(lambda t: tokenizer.tokenize(t))
        t1 = time.perf_counter() - t0
        print('Time taken', t1, 'sec')
        stemmer = SnowballStemmer("english")  # choose a language
        # Getting all the stemmed words
        print('Getting words stemmed ...')
        t0 = time.perf_counter()
        df['text_stemmed'] = df['text_tokenized'].map(lambda l: [stemmer.stem(word) for word in l])
        t1 = time.perf_counter() - t0
        t0 = time.perf_counter()
        df['text_sent'] = df['text_stemmed'].map(lambda l: ' '.join(l))
        t1 = time.perf_counter() - t0
        print('Time taken', t1, 'sec')
        bad_sites = df[df.Label == 'bad']
        good_sites = df[df.Label == 'good']
        df.head()
        cv = CountVectorizer()
        feature = cv.fit_transform(df.text_sent)  # transform all text which we tokenize and stemed
        feature[:5].toarray()  # convert sparse matrix into array to print transformed features
        from sklearn.model_selection import train_test_split
        X_train = df["URL"]
        Y_train = df["Label"]
        trainX, testX, trainY, testY = train_test_split(feature, df.Label)
        from sklearn.linear_model import LogisticRegression
        lr = LogisticRegression()
        lr.fit(trainX, trainY)
        lr.fit(X_train,Y_train)
        web=lr.predict([[url]])
        lr.score(testX, testY)
        Scores_ml = {}
        Scores_ml['Logistic Regression'] = np.round(lr.score(testX, testY), 2)
        # creating confusing matrix
        print('Training Accuracy :', lr.score(trainX, trainY))
        print('Testing Accuracy :', lr.score(testX, testY))
        con_mat = pd.DataFrame(confusion_matrix(lr.predict(testX), testY),
                               columns=['Predicted:Bad', 'Predicted:Good'],
                               index=['Actual:Bad', 'Actual:Good'])

        print('\nCLASSIFICATION REPORT\n')
        print(classification_report(lr.predict(testX), testY,
                                    target_names=['Bad', 'Good']))

        print('\nCONFUSION MATRIX')
        plt.figure(figsize=(6, 4))
        sns.heatmap(con_mat, annot=True, fmt='d', cmap="YlGnBu")



        if web == 'good':
            return render(request, 'success.html')

        else:
            return render(request, 'failure.html')
    else:
        return render(request, 'data.html')
"""

def predict(request):
    if request.method=="POST":
        url=request.POST['url']
        df=pd.read_csv(r"static/datasets/Phishing.csv")
        tokenizer = RegexpTokenizer(r'[A-Za-z]+')
        df['text_tokenized'] = df.URL.map(lambda t: tokenizer.tokenize(t))
        root_words = SnowballStemmer("english")
        df['root_words'] = df['text_tokenized'].map(lambda l: [root_words.stem(word) for word in l])
        df['text_sent'] = df['root_words'].map(lambda l: ' '.join(l))
        df.head()
        bad_sites = df[df.Label == 'bad']
        good_sites = df[df.Label == 'good']
        bad_sites.head()
        good_sites.head()
        print(list(STOPWORDS)[:10])
        data = good_sites.text_sent
        data.reset_index(drop=True, inplace=True)
        text = str(data)

        stopwords = set(STOPWORDS).union({'com', 'http', 'www'})
        wordcloud = WordCloud(width=800, height=800, background_color='white', stopwords=stopwords, max_words=400,
                              min_font_size=10).generate(text)
        data = bad_sites.text_sent
        data.reset_index(drop=True, inplace=True)
        text = str(data)

        stopwords = set(STOPWORDS).union({'com', 'http', 'www'})
        wordcloud = WordCloud(width=800, height=800, background_color='white', stopwords=stopwords, max_words=400,
                              min_font_size=10).generate(text)
        c = CountVectorizer()
        cv = c.fit_transform(df.text_sent)
        Xtrain, Xtest, Ytrain, Ytest = train_test_split(cv, df.Label, test_size=0.3, random_state=5)
        model = KNeighborsClassifier(n_neighbors=2)
        model.fit(Xtrain, Ytrain)
        print(model)
        ypred = model.predict(Xtest)
        con_mat = pd.DataFrame(confusion_matrix(ypred, Ytest), columns=['Predicted:Bad', 'Predicted:Good'],
                               index=['Actual:Bad', 'Actual:Good'])
        lr = LogisticRegression(max_iter=507197)
        lr.fit(Xtrain, Ytrain)
        lr.score(Xtest, Ytest)
        ypred = lr.predict(Xtest)
        print(classification_report(ypred, Ytest, target_names=['Bad', 'Good']))
        Xtrain, Xtest, Ytrain, Ytest = train_test_split(df.URL, df.Label, test_size=0.3, random_state=5)
        pipeline_ls = make_pipeline(
            CountVectorizer(tokenizer=RegexpTokenizer(r'[A-Za-z]+').tokenize, stop_words='english'),
            LogisticRegression(max_iter=507197))
        pipeline_ls.fit(Xtrain, Ytrain)
        bad = ['yeniik.com.tr/wp-admin/js/login.alibaba.com/login.jsp.php', 'fazan-pacir.rs/temp/libraries/ipad',
               'tubemoviez.exe', 'svision-online.de/mgfi/administrator/components/com_babackup/classes/fx29id1.txt']
        good = ['youtube.com/', 'youtube.com/watch?v=qI0TQJI3vdU', 'bestbuy.com/',
                'restorevisioncenters.com/html/technology.html']

        result1 = pipeline_ls.predict([url])
        phishing=Phishing.objects.create(url=url,output=result1)
        print(result1)
        if result1 == 'good':
            return render(request, 'success.html')

        else:
            return render(request, 'failure.html')
    else:
        return render(request, 'data.html')