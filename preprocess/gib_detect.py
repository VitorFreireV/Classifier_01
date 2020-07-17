#!/usr/bin/python

import pickle
from preprocess.gib_detect_train import avg_transition_prob


def gib_RandomString(word):
    model_data = pickle.load(open('preprocess/gib_model.pki', 'rb'))
    model_mat = model_data['mat']
    threshold = model_data['thresh']
    result = avg_transition_prob(word, model_mat) > threshold
    return result    

'''
while True:
    l = input()
    model_mat = model_data['mat']
    threshold = model_data['thresh']
    print (gib_detect_train.avg_transition_prob(l, model_mat) > threshold)
'''
