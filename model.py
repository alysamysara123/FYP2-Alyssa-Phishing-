import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import pickle

df = pd.read_csv('phishing_site_urls.csv')
df['url_length'] = df['URL'].apply(len)
df['has_at'] = df['URL'].apply(lambda x: 1 if '@' in x else 0)
df['has_maybank'] = df['URL'].apply(lambda x: 1 if 'maybank' in x.lower() or 'tng' in x.lower() else 0)

X = df[['url_length','has_at','has_maybank']]
y = df['Label']

model = RandomForestClassifier()
model.fit(X,y)
pickle.dump(model, open('model.pkl','wb'))
print("Model FYP2 siap!")