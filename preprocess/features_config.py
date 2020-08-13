HTML_LIST =['ForeignhyperlinksRule1',#1.13
        'URLofAnchorRule1',#1.14
        'LinksMetaScriptRule1',#1.15
        'FaviconD', #1.10, 2.29
        'statusBarCost', #1.20. 2.36
        'SubmittingEmailTo', #1.17, # 2.39
        'DisablingRightClick', #1.21, 2.37
        'IFrameRedFrameBorder', # 1.23
        #'NumberRedirect' : self.get_NumberRedirect,
        #'numberOfLinksPointPage': self.get_numberOfLinksPointPage, #1.28
        'ServerFormHandler',
        'EmbeddedBrandName', #2.26
        'Foreignhyperlinks', # 2.28
        'URLofAnchorCat', #2.34
        'InsecureForm', #2.30
        'RelativeFormAction', #2.31
        'ExtFormAction', #2.32
        'AbnormalFormAction', #2.33
        'FrequentDomainNameMismatch', #2.35
        'PopUpWindow', # 2.38
        'ImagesOnlyInForm', #2.42
        'PctExtResourceUrls',
        'IframeOrFrame',
        'LinksMetaScript',
        'checkTitle',
        'Numberofwebpages', #4.10
        'FakeLoginForm',
        'ForeignhyperlinksRule4',
        'Nohyperlinkfeature', #4.11
        'Copied_CSS',
        'Copyrightfeatures',
        'IdentityKeywords',
        'URLofAnchorRule4',
        'ErrorinHyperlinks',# LENTO
        #'ErrorinHyperlinksRule4':self.get_ErrorinHyperlinksRule4,
        'HyperlinksRedirections',# LENTO
        #'HyperlinksRedirectionsRule4':self.get_HyperlinksRedirectionsRule4,
        'CheckDataURI',
        'IFrameExternalSRC'
       ]

URL_LIST = ['UsingIPAddress1', #1.1
           'URLlengthRule1',  #1.2  
           'TinyService',  #1.3 
           'checkArrobaURL', #1.4, 2.5  
           'checkRedirectURL', #1.5, 2.24
           'checkDashDomain', #1.6
           'checkSubDomainMulSubDomain',#1.7
           'checkHTTPSDomainURL',#1.12, 2.20
           'StatisticalReports', # 1.29
           'numDotsURL', #2.1
           'NumDotSubDomain', #2.2         
           'pathLevelURL',  #2.3
           'URLlength',  #2.4
           'NumDashURL', # 2.5
           'NumDashDomain', # 2.6
           'checkTildeSymbolURL', # 2.8
           'NumUnderscoreURL', # 2.9
           'NumPercentURL', # 2.10
           'NumAmpersandURL', # 2.12
           'QueryComponents', #2.11
           'NumHashURL', #2.13
           'NumNumericCharsURL', #2.14
           'NoHTTPS', #2.15
           'DomainInSubdomains', # 2.19
           'DomainInPaths', #2.20
           'HostnameLenth', # 2.21
           'PathLength', #2.22
           'QueryLength', #2.23
           'NumSensitiveWords', # 2.25
           'NumArrobaURL',                   
           'KnowLTD',
           'get_PositionTLD', #F5
           'BrandNameURL', #3.2
           'numDots_URLRule4', #4.1
           'SpecialSymbol4', #4.2
           'URLlengthRule4', #4.3
           'SuspiciousInURL', #4.4
           'httpCountInURL', #4.6
           'BrandNameDomain',
           'NumNumericChars_Path',
           'NumNumericChars_Domain',
           'NumNumericChars_Subdomain',
           'RandomDomain',
           'RandomString',
           'DomainLength',
           'SubdomainLength',
           'checkWWW',
           'checkCOM',
           'numInterrogation',
           'numBar',
           'numEqual',
           'numArroba',
           'RawWordCount', 
           'AvaregeWordLength', 
           'LongestWordLength', 
           'ShortestWordLength',
           'StandardDerivation', 
           'AdjacentWordCount', 
           'AverageAdjacentWordLength', 
           'SeparatedWordCount',
           'OtherWordsCount', 
           'RandomWordCount', 
           'KeywordCount', 
           'BrandNameCount', 
           'TargetBrandNameCount',
           'TargetKeywordCount', 
           'SimilarBrandNameCount',
           'SimilarKeywordCount', 
           'ConsecutiveCharacterRepeat'
           ]

EXTERN_LIST = ['DomainRegsitrationLength',#1.9
               'AbnormalURL',#1.18  LENTO
               'AgeOfDomain',#1.24  LENTO
               'DNSRecord', #1.25  LENTO
               'GoogleIndex', #1.27  LENTO
               'SSLFinal_state', #1.8 LENTO
               'AgeSSL', #new LENTO
               'checkAlexa'
              ]
ALL_LIST = HTML_LIST + URL_LIST + EXTERN_LIST
