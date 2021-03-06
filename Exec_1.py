#########################################################################################
#
# CONSTANTS
#
# You can use these definitions in your implementation
#
#########################################################################################
from sage.all import *
import random
ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
NUM_DISKS = 36

ERR_INV_DISKS = "ERROR: DISKS ARE INVALID"
ERR_INV_ORDER = "ERROR: ORDER IS INVALID"

DICTIONARY_WORDS = ["ALAN", "ALICE", "ATTACK", "BOB", "CAROL", "CRIPTO", "CRIPTOGRAFIA", "SECURITY", "TURING"]

#########################################################################################
#
# STUDENT HELPERS
#
# You can create your own functions in this area
#
########################################################################################


def UOC_jeff_gen_key(disks=None, order=None):
    jeff_key = []

    #### IMPLEMENTATION GOES HERE ####
    if disks and order:
        t1 = all([len(uniq(k)) == len(k) for k in disks])##Disco contenido repetido
        if not t1:
            return ERR_INV_DISKS
        t2 = len(uniq(order)) == len(order)##orden repetido
        if not t2:
            return ERR_INV_ORDER
        t3 = all([len(disks) >= k for k in order])##orden mayor que numero de discos
        if not t3:
            return ERR_INV_ORDER
        t4 = all([len(uniq(k)) == len(disks[0]) for k in disks])##orden mayor que numero de discos
        if not t4:
            return ERR_INV_DISKS
        t5 = len(uniq(disks)) == len(disks)  ##Disco repetido
        if not t5:
            return ERR_INV_DISKS
        if len(disks) != len(order): #distintos numero de orden que de discos
            return ERR_INV_ORDER
        else:
            jeff_key = [disks[i] for i in order]
    else:##sin definir discos o orden
        for i in range(0, NUM_DISKS):
            jeff_key.append(''.join(random.sample(ALPH, len(ALPH))))

    ##################################

    return jeff_key


# EXERCISE 2: Implement Jefferson disk cipher
#
# Function UOC_jeff_cipher.
# * Parameter key: a list with the key, as generated by UOC_jeff_gen_key.
# * Parameter message: string, message to cipher
# * Returns: string with one of the possible ciphertexts corresponding to the specified message under the key
#

def UOC_jeff_cipher(key, message):
    ciphertext = ""
    #### IMPLEMENTATION GOES HERE ####
    position = []
    for i in range(0, len(message)):
        position.append(key[i].index(message[i]))
    offset=randint(0,len(key[0]))
    for i in range(0,len(position)):
        ciphertext=ciphertext+key[i][(position[i]+offset)%len(key[0])]
    ##################################

    return ciphertext


# EXERCISE 3: Implement Jefferson disk decipher
#
# Function UOC_jeff_decipher.
# * Parameter key: a list with the key, as generated by UOC_jeff_gen_key.
# * Parameter message: string, message to decipher
# * Returns: string the plaintext or list with all candidate decryptions
#

def UOC_jeff_decipher(key, message):
    result = ""
    #### IMPLEMENTATION GOES HERE ####
    position = []
    result_list= []
    for i in range(0, len(message)):
        position.append(key[i].index(message[i]))
    for j in range(0,len(key[0])):
        result = ""
        for i in range(0,len(position)):
            result=result+key[i][(position[i]+j)%len(key[0])]
        result_list.append(result)
        if result in DICTIONARY_WORDS:
            return result
    ##################################

    return result_list


####################################################################################
# TEST CASES EXERCISE 1
####################################################################################

def test_case_1_1(name, num_its):
    res = []
    for _ in range(num_its):
        keys = UOC_jeff_gen_key(disks=None, order=None)
        t1 = len(keys) == NUM_DISKS
        t2 = all([len(uniq(k)) == len(k) for k in keys])
        t3 = all([all([l in ALPH for l in k]) for k in keys])
        res.append(t1 and t2 and t3)

    print "Test", name + ":", all(res)


def test_case_1_2(name, disks, order, exp_result):
    keys = UOC_jeff_gen_key(disks, order)
    print "Test", name + ":", keys == exp_result


test_case_1_1("1.1", 50)

disks = ['CAOXPFJTSEBZRYIGDLKQUVNWMH', 'DZMIKNWLFQRVGUXOCPJHBAETSY', 'STIZDYBJAWXMEHUCOKQRNGFVLP',
         'PMSYNWGEAIRQHVBZTJOUCFDKLX', 'HGBWICUQPOMRVJLFXTKSZYADEN', 'EGZMJLRAHOCTUFISKWNBVYQPDX',
         'CSWFLPGTRZOAHKBQVDYUMENIJX', 'UOLQSKWHFAGJPVRMBXZIYDNECT', 'QHPUSVKRTADJYNXCFIGBOZEWML',
         'LAPEYZTMGRWUONSCIKFVBXQHJD', 'MEWTZIKANQHOPUBFVDGRLCXSJY', 'FLZHSRIBQKPDEUVMXGTAWYNJOC',
         'KQFWCBGXZSHDOTPLIRENYVUMAJ', 'CGZKJNPIREAMWBTLFUYVSHOQDX', 'CBWKJUYRXGIAMESLOVHZFDTQPN',
         'FQAJCBLRMVWPTZDKINGXSHYUEO', 'NMJCHVKFTXYSLPWIRADZGOBUEQ', 'WNLXZKCBVJRUPESTMOYIHAGFDQ',
         'OBTJFYCKXPDIGRHNUVQLEMAWSZ', 'BMZSJTVKPFODUWCEGHLARNQXYI', 'EGUNIFSHCYBDRZQKPWTVXMOLJA',
         'XYKVHEZQRGJSMDLAWONPBIFCUT', 'ITAEURHYGJMFXLOCWKSVBPDQZN', 'DNEVCQZPLGTUWJMIHOAKSYRXBF',
         'GTVASZYELNUBFCHKRPWJXDMIOQ', 'RDFLTWIHXJKBPANMOGYSEVZQCU', 'LJODBASUVCFHIXWZPKQNTRGEMY',
         'KRVXOMCYQTDLHNZGSUJAEIBWFP', 'UFGMEHRBZLYVTSXDIKAPOCWNJQ', 'XVZWBMUCYQPROEFTAGHNKDJLIS',
         'LYNBVDZQEMRSPFCKUWOHITXAGJ', 'AICVPNSRDHEXFOWLMZUBYKTJGQ', 'GVCDLQMWHZKROXUTFPBSYNIAEJ',
         'UTONCMBHDXLKFGYASJQPVRWEIZ', 'MZOLFWTEJCDKPVIQBUSRAYHGNX', 'ALDXRHGIKFPNTCWSEJOUZQBMVY']
order = [23, 20, 26, 3, 30, 21, 4, 18, 14, 34, 9, 24, 29, 22, 2, 11, 28, 35, 25, 12, 16, 7, 17, 32, 13, 6, 8, 0, 10, 5,
         1, 27, 33, 19, 31, 15]
exp_result = ['DNEVCQZPLGTUWJMIHOAKSYRXBF', 'EGUNIFSHCYBDRZQKPWTVXMOLJA', 'LJODBASUVCFHIXWZPKQNTRGEMY',
              'PMSYNWGEAIRQHVBZTJOUCFDKLX', 'LYNBVDZQEMRSPFCKUWOHITXAGJ', 'XYKVHEZQRGJSMDLAWONPBIFCUT',
              'HGBWICUQPOMRVJLFXTKSZYADEN', 'OBTJFYCKXPDIGRHNUVQLEMAWSZ', 'CBWKJUYRXGIAMESLOVHZFDTQPN',
              'MZOLFWTEJCDKPVIQBUSRAYHGNX', 'LAPEYZTMGRWUONSCIKFVBXQHJD', 'GTVASZYELNUBFCHKRPWJXDMIOQ',
              'XVZWBMUCYQPROEFTAGHNKDJLIS', 'ITAEURHYGJMFXLOCWKSVBPDQZN', 'STIZDYBJAWXMEHUCOKQRNGFVLP',
              'FLZHSRIBQKPDEUVMXGTAWYNJOC', 'UFGMEHRBZLYVTSXDIKAPOCWNJQ', 'ALDXRHGIKFPNTCWSEJOUZQBMVY',
              'RDFLTWIHXJKBPANMOGYSEVZQCU', 'KQFWCBGXZSHDOTPLIRENYVUMAJ', 'NMJCHVKFTXYSLPWIRADZGOBUEQ',
              'UOLQSKWHFAGJPVRMBXZIYDNECT', 'WNLXZKCBVJRUPESTMOYIHAGFDQ', 'GVCDLQMWHZKROXUTFPBSYNIAEJ',
              'CGZKJNPIREAMWBTLFUYVSHOQDX', 'CSWFLPGTRZOAHKBQVDYUMENIJX', 'QHPUSVKRTADJYNXCFIGBOZEWML',
              'CAOXPFJTSEBZRYIGDLKQUVNWMH', 'MEWTZIKANQHOPUBFVDGRLCXSJY', 'EGZMJLRAHOCTUFISKWNBVYQPDX',
              'DZMIKNWLFQRVGUXOCPJHBAETSY', 'KRVXOMCYQTDLHNZGSUJAEIBWFP', 'UTONCMBHDXLKFGYASJQPVRWEIZ',
              'BMZSJTVKPFODUWCEGHLARNQXYI', 'AICVPNSRDHEXFOWLMZUBYKTJGQ', 'FQAJCBLRMVWPTZDKINGXSHYUEO']
test_case_1_2("1.2", disks, order, exp_result)

disks = ['CYPKEZFBHTOASGDNUIQMXLVWJR', 'ZTUIMSFDRBAEOHCGPYLWQVJNKX', 'MRHYKNPWGAQTOXZBDIFLJSVCUE',
         'MZHNFYQVDBLOEXSCTJWAPKUIRG', 'SFXNTPBHWOJQAMVZGDCKUERIYL', 'XWZGDIFLYHTQMKUCBJPSVEOARN',
         'FRQSBMXPHAKITZJCUWLVGNYDOE', 'DXGFPBIMAJTZCLRSUOWVEYHKNQ', 'BFULXZKPRSCWHIODVGEAJNMYQT',
         'VITSEZRDUWXFGBHOKCNYJQMAPL', 'MBAVDXYPZCUKWRNGOIFJQLETSH', 'RDYBSNTCPXAIOFLEZMUWGJKVHQ',
         'JLMPQTGAZKCXIRUSHVWOEDFNBY', 'BJFAUKNTMYGPCDELQSXOIHZVWR', 'RUSFIQMEACKWPOXHJZVNBDYTLG',
         'OUHFGLNVRMYIBTEWSZCKAPJXDQ', 'JAFMIQZHCGLTRXWYSDBKUOENVP', 'EDURQLICNZVWJGKSTMAOPXHBYF',
         'EBQSHVYAUZPOTCGRWMDNLJKFXI', 'IWPDNMQTXKOULJCRVZFHSGEBAY', 'NORLEDQFTICWKYSAVHZXPUBGJM',
         'BSAUOGXRQKPYHEDZFWNTIJLCMV', 'WVKDBPECHMFXUGNOIZRQLSTJAY', 'YDMHZWITBRVPFNJOACSQUXEKLG',
         'WISUPCDTBZKGOLYJHAQVXFMREN', 'WFVJSQHAUDCIGNPBOKELMXZYRT', 'HRWZBGXCLJKPOVQEMYSDFITUAN',
         'LDVWJYKQHMSEFZUOIBNTRCAPXG', 'BVNIAQMTHYOZPRKGLDUJXEWCFS', 'DSBQLVEMRFTWNJIKUZOGXYHCPA',
         'KFNEPOJWDTBLYRMXCQUZGHVSAI', 'GSTLZPVYDOXCWRFQMAKIEUBNHJ', 'JWDZXNGAOSUQKRTMVHFBYCILPE',
         'UDPWCLNVYEIFHJAXSTRGBQOMZK', 'HOUWDJBPQTYFREVLMSCZAKINGX', 'HDUXOZVTIYKBPFGALEJWQRSNMC']
order = [32, 11, 4, 12, 16, 26, 22, 28, 35, 23, 9, 0, 18, 10, 20, 1, 21, 31, 3, 14, 24, 19, 7, 6, 34, 27, 13, 17, 2, 33,
         15, 5, 29, 8, 30, 25]
exp_result = ['JWDZXNGAOSUQKRTMVHFBYCILPE', 'RDYBSNTCPXAIOFLEZMUWGJKVHQ', 'SFXNTPBHWOJQAMVZGDCKUERIYL',
              'JLMPQTGAZKCXIRUSHVWOEDFNBY', 'JAFMIQZHCGLTRXWYSDBKUOENVP', 'HRWZBGXCLJKPOVQEMYSDFITUAN',
              'WVKDBPECHMFXUGNOIZRQLSTJAY', 'BVNIAQMTHYOZPRKGLDUJXEWCFS', 'HDUXOZVTIYKBPFGALEJWQRSNMC',
              'YDMHZWITBRVPFNJOACSQUXEKLG', 'VITSEZRDUWXFGBHOKCNYJQMAPL', 'CYPKEZFBHTOASGDNUIQMXLVWJR',
              'EBQSHVYAUZPOTCGRWMDNLJKFXI', 'MBAVDXYPZCUKWRNGOIFJQLETSH', 'NORLEDQFTICWKYSAVHZXPUBGJM',
              'ZTUIMSFDRBAEOHCGPYLWQVJNKX', 'BSAUOGXRQKPYHEDZFWNTIJLCMV', 'GSTLZPVYDOXCWRFQMAKIEUBNHJ',
              'MZHNFYQVDBLOEXSCTJWAPKUIRG', 'RUSFIQMEACKWPOXHJZVNBDYTLG', 'WISUPCDTBZKGOLYJHAQVXFMREN',
              'IWPDNMQTXKOULJCRVZFHSGEBAY', 'DXGFPBIMAJTZCLRSUOWVEYHKNQ', 'FRQSBMXPHAKITZJCUWLVGNYDOE',
              'HOUWDJBPQTYFREVLMSCZAKINGX', 'LDVWJYKQHMSEFZUOIBNTRCAPXG', 'BJFAUKNTMYGPCDELQSXOIHZVWR',
              'EDURQLICNZVWJGKSTMAOPXHBYF', 'MRHYKNPWGAQTOXZBDIFLJSVCUE', 'UDPWCLNVYEIFHJAXSTRGBQOMZK',
              'OUHFGLNVRMYIBTEWSZCKAPJXDQ', 'XWZGDIFLYHTQMKUCBJPSVEOARN', 'DSBQLVEMRFTWNJIKUZOGXYHCPA',
              'BFULXZKPRSCWHIODVGEAJNMYQT', 'KFNEPOJWDTBLYRMXCQUZGHVSAI', 'WFVJSQHAUDCIGNPBOKELMXZYRT']
test_case_1_2("1.3", disks, order, exp_result)

disks = ['PUTZNKHOCFBEAIDVGJMLYWQXSR', 'VPHLAQEFNRIKYWJDOCZBUMSTXG', 'LSVMJQOBYCPENGZWRAXKIDHFUT',
         'DVTOGLSZMEYBPHNFQCRIWAJXKU', 'CJXIKBOMWFUDGZHYNVQREPTALS', 'WYQKNTGFHDXEPJUIMRSLZAOVBC',
         'TFSHBXNVKRZDICOQAYMLEWUJPG', 'ONBTVXRHGEQMIYJZKLACPUFSWD', 'IZCYRNXGHLTDVJQPSOAUBFEKMW',
         'MCIDEKPNJSUGQYFBOWTVLZXHRA', 'EVAPIYCNXWQOFKJLRSGHTMDZBU', 'GQJBMNXDOUFAZTPLYSVKRCHWEI',
         'WEUPJGHVMOZRLFYDIQNAXSCBKT', 'JZONEHTBSKXUPIMRGWACDQFYLV', 'PNXIBJZKAMYEWORUVGDHLFCSQT',
         'MQGFHZSAPRKBOXUYVIJTLWNCED', 'UMJQPVWRTIYAZBEOLKHCDFNGXS', 'QMLEGHSCIPKNVDTAJUBXRZWOFY',
         'UFODQMTGAZNBCXYRPIWHJSEVKL', 'OYUWNIFGQDVCPTLXEHAMRSKBJZ', 'QGZBVYTULFRONJDSWPXKMIACEH',
         'WCMLHNFRPGEQZTOJAIBUKDXVYS', 'JKWMBFYXAPZRCHDSIUQGVELONT', 'AITGHDKSJQWVRUXCNFMLYBOEPZ',
         'JIMFPGRESCTOWUNBADQLKZXYHV', 'IPJFHXWSYOMDRNGBZCLUQVTEKA', 'LKSAYEXMWNPRQJIHFUZVTODCGB',
         'DPLNJOIRVTWFKCUBHGYASMZQEX', 'TIESQBDRVFLGWOAMPZHCNJYKUX', 'RTSXPCJHLKBMZYEGONQWIFUAVD',
         'TSIPBNZMUDHALXWYFVKRCEGJQO', 'EZDBFOLUJKRQACXHGPYNWITSMV', 'VLAPCKEBURDNJOYZMWSIHXFQTG',
         'GWDLJNSMAIRVKHYUPTXEZFBCQO', 'DKOUFCVGZHSWYIMXQRTBPALEJN', 'XEPAGWLQMCFSKZJYIBRHNOUVDT']
order = [29, 15, 13, 35, 6, 30, 20, 7, 2, 0, 25, 32, 14, 12, 5, 24, 4, 11, 23, 27, 22, 34, 33, 18, 21, 10, 17, 3, 31,
         28, 9, 16, 8, 26, 1, 19]
exp_result = ['RTSXPCJHLKBMZYEGONQWIFUAVD', 'MQGFHZSAPRKBOXUYVIJTLWNCED', 'JZONEHTBSKXUPIMRGWACDQFYLV',
              'XEPAGWLQMCFSKZJYIBRHNOUVDT', 'TFSHBXNVKRZDICOQAYMLEWUJPG', 'TSIPBNZMUDHALXWYFVKRCEGJQO',
              'QGZBVYTULFRONJDSWPXKMIACEH', 'ONBTVXRHGEQMIYJZKLACPUFSWD', 'LSVMJQOBYCPENGZWRAXKIDHFUT',
              'PUTZNKHOCFBEAIDVGJMLYWQXSR', 'IPJFHXWSYOMDRNGBZCLUQVTEKA', 'VLAPCKEBURDNJOYZMWSIHXFQTG',
              'PNXIBJZKAMYEWORUVGDHLFCSQT', 'WEUPJGHVMOZRLFYDIQNAXSCBKT', 'WYQKNTGFHDXEPJUIMRSLZAOVBC',
              'JIMFPGRESCTOWUNBADQLKZXYHV', 'CJXIKBOMWFUDGZHYNVQREPTALS', 'GQJBMNXDOUFAZTPLYSVKRCHWEI',
              'AITGHDKSJQWVRUXCNFMLYBOEPZ', 'DPLNJOIRVTWFKCUBHGYASMZQEX', 'JKWMBFYXAPZRCHDSIUQGVELONT',
              'DKOUFCVGZHSWYIMXQRTBPALEJN', 'GWDLJNSMAIRVKHYUPTXEZFBCQO', 'UFODQMTGAZNBCXYRPIWHJSEVKL',
              'WCMLHNFRPGEQZTOJAIBUKDXVYS', 'EVAPIYCNXWQOFKJLRSGHTMDZBU', 'QMLEGHSCIPKNVDTAJUBXRZWOFY',
              'DVTOGLSZMEYBPHNFQCRIWAJXKU', 'EZDBFOLUJKRQACXHGPYNWITSMV', 'TIESQBDRVFLGWOAMPZHCNJYKUX',
              'MCIDEKPNJSUGQYFBOWTVLZXHRA', 'UMJQPVWRTIYAZBEOLKHCDFNGXS', 'IZCYRNXGHLTDVJQPSOAUBFEKMW',
              'LKSAYEXMWNPRQJIHFUZVTODCGB', 'VPHLAQEFNRIKYWJDOCZBUMSTXG', 'OYUWNIFGQDVCPTLXEHAMRSKBJZ']
test_case_1_2("1.4", disks, order, exp_result)

disks = ['XW2ATYK4GB7DIVHJL59ZONQ1F8PS0UMC36ER', 'VPZS17TL0B59OECRWHYAMX48UGQ2KDF63JIN',
         'DY6U7HJRN15LS8VET2PIFZWXAO39QGC4BK0M', 'I95ZDPOYJFRXQA8V0W7426HNBELSUC3GKT1M',
         'JD0Z7IT1PV2F4Y3WSQ5AULHOC9RKXGB8MNE6', 'P63BSJKEO5L20INYCMDVUTQAZ7W48FXG1R9H',
         '7GOI3VM1SZU2PHRAQYFD58KCX6B40LENW9TJ', '0567B4T38JUDE12GKNYSOZHRX9IVMQFPCALW',
         'BZGENPKI2584WRJC3MH7S6TYD9VXLUAF1O0Q', 'XZN8GTY5H7VWOB6AKUQ1EL0FRSI43MC2D9JP']
order = [2, 7, 0, 8, 3, 1, 5, 9, 6, 4]
exp_result = ['DY6U7HJRN15LS8VET2PIFZWXAO39QGC4BK0M', '0567B4T38JUDE12GKNYSOZHRX9IVMQFPCALW',
              'XW2ATYK4GB7DIVHJL59ZONQ1F8PS0UMC36ER', 'BZGENPKI2584WRJC3MH7S6TYD9VXLUAF1O0Q',
              'I95ZDPOYJFRXQA8V0W7426HNBELSUC3GKT1M', 'VPZS17TL0B59OECRWHYAMX48UGQ2KDF63JIN',
              'P63BSJKEO5L20INYCMDVUTQAZ7W48FXG1R9H', 'XZN8GTY5H7VWOB6AKUQ1EL0FRSI43MC2D9JP',
              '7GOI3VM1SZU2PHRAQYFD58KCX6B40LENW9TJ', 'JD0Z7IT1PV2F4Y3WSQ5AULHOC9RKXGB8MNE6']
test_case_1_2("1.5", disks, order, exp_result)

disks = ['CKQYZJSXNAWOVDBTGRLIMUFEPH', 'RCDGPZYSQWAJINTEHOMKXUBLFV', 'EPCXTJYLSMDKRAVNZUHQOWFIBG',
         'EUVWTCQJLZGAKMNXIDHFPSORBY', 'MALPIUGHOEWRCZKXYFTQBNSJDV', 'JKVXSMZYCQALTUNRPIWFDOBGH',
         'OGBVJKCLTYAXPIEFZUQMNHWDRS', 'HYDMSCIUNWGTZLOKFBVAEPQXRJ', 'MXDYCRNPOSTQVJGBLWUFKAEIHZ',
         'BDFWJRSGQLTEXCIVYZAUKMONHP', 'QBTNEFZAVHPCGDISRJXYOWMLKU', 'EFDBGRPZSYTOXCLQVHNMJUAWKI',
         'IWAMPNGLETRFYJVHKQZOXSBCUD', 'DRFBGLWKESYCIJMTHPXUNZAQOV', 'ZIWATDQEVLJYUGNOXFBRPMHKCS',
         'TPQMKUYRILOEANXGVFZBHWCJDS', 'ENOLDPARIYUVXMWZHJKTSQCGBF', 'SLNEJKRVBUPOXDGYAHQZFICMTW',
         'OLBCFGVDIJXRQZWPMANHUTKYES', 'JPWKXYEMANCZIDBOGLFHSVTQRU', 'CDAFJBXRMGKNYEHZIPTSQWUOLV',
         'KMSYXWQNLPUAJZRGTCHIOFEBVD', 'WGHSPIZVNQFACKBRTMLEYUXDJO', 'PUSBAKOQHFDYJWMNLXZCEVTIRG',
         'FJMTLCDAIPRWYXBHQZVESUKGON', 'NAIFWMVZXCDJOPRSEHTBLYUKQG', 'PAHLZYXBUIJCSMRGWVQOFKTEND',
         'ECZSHDKAXVFJQGRIWNTBMUPYLO', 'BQMLUKXZOINWVGDHRFTYAPCSEJ', 'JQWGKASYLZMTNRHCBXFEDUIOVP',
         'ZHRFLOBUWACSIYKQDTEMVGXNJP', 'JOGWFCQXHIPAYKDMSTRVBULZEN', 'IKAZWBLCMESDXFGNYPOQHTRUVJ',
         'WEKFACMQYVPIDBNGUHRZSLJOXT', 'WCLQXYMZAVGPKNJSHIOBRDUTFE', 'VFZYQBWIHELGOPCTDSJRAXUKMN']
order = [15, 3, 7, 28, 30, 26, 21, 27, 35, 10, 31, 18, 29, 6, 14, 25, 0, 5, 9, 19, 8, 12, 22, 11, 13, 24, 4, 23, 17, 1,
         16, 33, 32, 20, 34, 2]
test_case_1_2("1.6", disks, order, ERR_INV_DISKS)

disks = ['ACHIDUPNVKWETZBQJYLFGRXSOM', 'ULGJKPBIERVZOXSQHANDTYWFMC', 'IJYQOCTMAZVKXLFSPWGEDBHUNR',
         'ZQSIKOGPMRALBTDCNYVFEHUWJX', 'LTWPVOHENUQJYAXCIMBZFGKDRS', 'BIMNSHALFREWQPKXGVJDUYZOCT',
         'FWLYZODIEAMKSUTPRCQHVXBGJN', 'QOLCZVAMJWEDIBYHPNSUGXKRFT', 'BHZURYFGWEPKANVOTQIXCSDMLJ',
         'AXPOCZRSVDWTUKJGLFNIMBYQEH', 'ZEPYNQLROVCATJKUDMBSFIHXGW', 'NYEARLXKPCOWZUQSJMFVTDGBHI',
         'UDWTNCJMOBEFYPZLSRHAXVGQIK', 'RPLVGEZSHFYKOAIDTXMQCWJUNB', 'JLWQPEOKUZVMHTSFDRIGNCBXAY',
         'NRGYSIBTWOXHELVZAJFUQPCKDM', 'SIVXYHUACFTPKBZNWMLJEDORQG', 'HAIZBJPRMTCSQFVXKNUOYDELGW',
         'PFHWUSBRXINZJGQCOKDVMLEAYT', 'VGFQAXIYZDSCHLWPNEBJTUKMOR', 'LQZVBOATGNRCXFYSDKEWIUHJPM',
         'ENJYMDISKBRVGZQOTHUACLXPFW', 'XORFYLPGCDQBITJVKZASNMWHUE', 'JGCQMSRAPUDYFKBNWEHIVOZLXT',
         'KCNUEWQFDZGMAYIVRSPJLTBHXO', 'BSONDMIAJVQCEZTHKRFUWYLPXG', 'EPWTUQKHMCDOYNXFSGJLVIZRBA',
         'LDXHRWIGFUPNBMAZSKJCQVYETO', 'PAXGLBFNUMYQJDROHCVSTZKIEW', 'SDNMUOCRLJQEYBZHGVWKAPIXFT',
         'DRKAQXFTYCHNEWPJBGSIOMULVZ', 'QSVAYJUWKRGZPLHFTNCIEDMOXB', 'KRNBWSMOCFXYVPUEDQIATHZJLG',
         'NAYUEJRDWIKQHVCOFTZMPXLBSG', 'EROAVFHNLCXDQZUWYPGJTIMBKS', 'ACHIDUPNVKWETZBQJYLFGRXSOM']
order = [9, 12, 0, 35, 3, 21, 15, 28, 17, 22, 16, 19, 30, 1, 4, 14, 29, 24, 11, 23, 6, 34, 32, 8, 26, 13, 18, 10, 7, 27,
         2, 5, 25, 20, 33, 31]
test_case_1_2("1.7", disks, order, ERR_INV_DISKS)

disks = ['UNDOBSJKYIAQMRGETVLZXPCHWF', 'NALISMGWEYPVHJFDZXUCBRQKOT', 'UYRDAPWHMXNEZBIQSLVOTKJCFG',
         'YPBHFTRWALIGCJVXDEMOZQUSNK', 'XKIUNTZRFSLDHBGQCJAWVPOEMY', 'QLURKVTHGYDIEPZBWCNSJFOXAM',
         'YMPGOAIUJHVLTKQENSDWBRFXCZ', 'XJFCVLAKNQIEGHMRWBPSUZTOYD', 'MAPFZHEVJWLCXKONIGYRUTSDQB',
         'KEJRBIUOWGHCVMNSPTFLYZXADQ', 'KUBPVJTRXDLHGCOSAFZQWIMENY', 'VKFUBHLSWDGXOREJTNZMQPYACI',
         'LOKYMFRQXUDZTGEVIWSHACJPBN', 'LZRQXHIKJTFMSYEAUDNWCBGPOV', 'INTQSPYBFEKWHJZGMORXACLDUV',
         'HQAVXGFETPIONYUDKSBZRMCLWJ', 'ISBFJGHTEMLYODXZRKNAQPCWVU', 'LVMEDUQJIZBWFXPRKSGTYHCOAN',
         'BUGQKTHJWMXLAEZFNYOSIPCRDV', 'JVSMUBNERKXPAOWFTICGHLDZQY', 'YBKHQZCJXETUVOWLINDFRPMGSA',
         'RGYXHLDOQTVUSCIAKPZEJWNBMF', 'UBIFLXDWPTMAQRSNCHKOZVYGEJ', 'HRMGZUCKWIJOQFSYPLADTXNVEB',
         'SXCHOBMKTGWPVJIDUZLRQAFEYN', 'HDVQWBTNGSIRKZLEXOPUJYCAFM', 'MFGXIDOJTPZLQHWYKEURSVACBN',
         'IVNUXRAOCYLEZQKPHBJDFSWTGM', 'LKTBYSGJUZCDRWVNEHQPFXAOMI', 'NOUAVSLIXCFTMHKGYPWDBQZERJ',
         'PMXZKWAFYINRSCJEUOGDQHVTLB', 'JCYKAHNPWEMGXDLTRBFOIZQVSU', 'KUTQPNZERBMVDGLFCYJAWXHSOI',
         'UHONZXFGEBRPWTDYILSMKAQCJV', 'GYWKASVPQRXUFOIBTLDHNJMZEC']
order = [24, 5, 4, 21, 15, 33, 32, 28, 30, 26, 0, 27, 23, 25, 8, 19, 20, 2, 34, 18, 6, 29, 17, 31, 10, 35, 7, 1, 22, 14,
         11, 3, 16, 13, 12, 9]
test_case_1_2("1.8", disks, order, ERR_INV_ORDER)

disks = ['MNZEXTVIPOARDCJBYSUGHLWKQF', 'XSFYVDJEZURAWCPQGNTIMBKHOL', 'JCVNSDZUILEFPOTKABHYMXQRGW',
         'TCZAUSPLMVQBFOIRXHEKGWDYJN', 'CAVQZDWLTJFXNMUORKSBPEIYGH', 'GYVSIJRZNKFQPAULCHMTWOEDBX',
         'RXNMLCJFUYDIGHATPZWVBESQOK', 'RFBLTPJZEAKCHNIQUXMSWVODYG', 'PRJGNSMCIDKWHEYVTALXZOUFBQ',
         'UBJCVQWIPKARXYDMLFTOZHNGSE', 'XTVWQUYANLIRMGCPKHSEBFJOZD', 'BIJSUAVWHXRTCZEPMGKNLYQDOF',
         'SZAORLBHDMGECQVNXJPKFWUYIT', 'ITHYAXNZVJSKCUBMWDLFEOQRGP', 'ARNOGBKZMJIXSTPLWHYQEVFDCU',
         'HFLOGSNXAPEJZMQUVBYDWCRIKT', 'KWTBYRISOMLQVDJEUHFGXZCNPA', 'QRPJDTINOUZGAYBXKHWSECFMVL',
         'TNWBYSVOQRDFICLAUEZXKGMHPJ', 'MYDPHJUWGNKSTLCOIEBXAZQVFR', 'FDOSMKGJEWTIHAPCVNLUBZYQXR',
         'IZNUVEFJGYDWPAQKXMBOSLHCRT', 'LVKSWPFQYEMUNZBGITOXARHJDC', 'KCFMNSLHROJYBGWAUTVIZQXPED',
         'QGKXJBDPROWMLIHSZYAVENFCTU', 'UQLIPAEJKDCGTFXZSHWYOMVBRN', 'SYADBMGHXUECKNFZWOPIRLQVTJ',
         'NUPDSYLQKFAIBWORJHCMZGTXVE', 'EDURGXMWFKYPITQSNHJAOZCBLV', 'JDRXNELFHBGWMTOVKCZIYUQSAP',
         'ZGVEDBLXQOCJMFIUSYHKAPNWRT', 'OPVRUHYWZMIJTKNSBFQGADLECX', 'NFJXZKQGHOLRUDPBYWCAVSMTEI',
         'TEVWRQKMDJBYCNAOPHSFIUZLGX', 'NEUMGPVKRYJZCIBHODTQSXFALW', 'AFOUPHGERWJYZCXDMBKQILTNVS']
order = [9, 17, 13, 34, 16, 19, 27, 24, 31, 10, 4, 14, 2, 11, 5, 32, 15, 18, 1, 26, 12, 13, 3, 6, 30, 23, 25, 28, 20, 7,
         22, 0, 35, 33, 21, 29]
test_case_1_2("1.9", disks, order, ERR_INV_ORDER)

disks = ['OXCQLHAUFNMPGBTYKEDRIWVZSJ', 'ARKDUJMTHXYNISCEBOQWVFZLPG', 'NVCLUZEXIKSTORQFBAPWDYHGJM',
         'KEIHDVLAWSPJUQZFGOCNMYTRBX', 'OTPXFEAQMGNWSIHRBLZYJUDCKV', 'MVAGNDPWTOJXQLIFEZKHSBRUYC',
         'QHESXZPJGLANFVOTMBKWUYCRID', 'TRVEKADUNCMOHBYXZLFQWPSGIJ', 'GSWDHOTRVMNQEPUCLFZBKXAJIY',
         'ODSMREPAZHJLXFWNUYBGCTKQIV', 'ZUDSJHGAQYWEOPXMRLFNKVCITB', 'ZCSTQKEHDLPURBYIFJVXGOWAMN',
         'CVUNTQDAOLIEXRWBYFSZKGMHPJ', 'YBEKLGXWRDCTFZPVAHNMJOISQU', 'LABCOXVEMJRYKDZHPGUIFQSWNT',
         'ECYQBAOWTPFSLZGXUVDNMJRIHK', 'NAVBYEXHSUIRQDLOCJPFGTMWZK', 'NEZDYXOKPAQCLWFIUJGVTMRBSH',
         'OECGQUIDRZLBWSPVYKNJHTAFMX', 'KJZFDEXMIAQVNLGRHOWPCBUYTS', 'JNLRFSCYQZKOTIVPEHXGBADUMW',
         'EGSMTPKLUZAVOBHNRCFJIQWYDX', 'KQHJNZVGAXYIDOFTSBCURWEMPL', 'ZMWJCYOGQESDBANLTPXHURFIVK',
         'XDLTZEHCSQUNJWIVPGYKBFOARM', 'XQOVTFSENDLBAYHCGMWRKPIUZJ', 'TULFIQWGEMAYZDHVORBCNJXPKS',
         'UEMBTFORJYWCIGXLHDZSNQKVPA', 'SRHMUXWCPNGTBVQFDELIZKYOJA', 'PIBAYHLVUOSWFZDKRMNTXCQJGE',
         'CEJHKGLZRTXPFBDQNVUYSMOIWA', 'IHZXEOGCNKAVFTUBWYSLRPJQMD', 'OKTRCNXBVDHZGIWPMEAUYJFSLQ',
         'CDHFNGTYZQPJSBKVEMXIWUOLAR', 'MQPKVHIASFJNTCEWGODYBXLRZU', 'IAXUQYJWHLPBFMVGSDCEONZTRK']
order = [27, 25, 33, 12, 35, 0, 15, 22, 21, 3, 20, 31, 11, 13, 9, 1, 14, 6, 8, 23, 28, 37, 17, 5, 16, 18, 24, 10, 7, 19,
         29, 32, 26, 34, 2, 4]
test_case_1_2("1.10", disks, order, ERR_INV_ORDER)


####################################################################################
# TEST CASES EXERCISE 2
####################################################################################

def test_case_2(name, key, message, exp_c):
    c1 = UOC_jeff_cipher(key, message)
    c2 = UOC_jeff_cipher(key, message)
    c3 = UOC_jeff_cipher(key, message)

    print "Test", name + ":", c1 in exp_c and c2 in exp_c and c3 in exp_c and (c1 != c2 or c1 != c3 or c2 != c3)


key = ['AWORMLBCGKQPTSIYHFNZJUEVDX', 'DSELUMBJPYIGQXKAVZCWFTRNHO', 'GIDYLVKJEQRBCFTAMWXZPSHONU',
       'KMVYTLEQZPOCAGWDJSUFBIRHXN', 'WPMXBOQRYNTZGDIHVCLSFKAJEU', 'QUJXFERHICLWYOATSDKBNGVZMP',
       'FHUAIOGQPCEDSYJNWXKBMLRZTV', 'XQMONDRZWJKBTAUHLFYSGCVIPE', 'ORCUTHYGVEKNXJSZFPDIBMQALW',
       'GXUCOATVFLWRHZJQYNSDIMPBKE', 'XODNHBZIESAQFYKTUPWVLCMGJR', 'KWXTFVJEPAIZSYOLUGNMCHBRDQ',
       'PDUMKASBHJTLYNVQZEXFCIGORW', 'WDEKIYHQSCANGFBXTRLZPUVOMJ', 'MSTGCHIDVPOKQRLWBXZYJAENFU',
       'OFGMKIADHUTSCELRPVQNJYZXWB', 'JEZQSTWKYPFBAXIRCNUOHDLMVG', 'KCGUPFRTEJQXSHDMAIYVNLBZWO',
       'CQBIKAGMELWZPDNFRJUHSVOXTY', 'ALJPTIFWNCSHVUOYXQMBEDZKGR', 'DFEKPCQMBLAIGYJTXZRUSONVWH',
       'NAHCOJFGLYRSPDBVXEZMUIWQKT', 'TXKCMJPZHYQDGULIFBSOREANVW', 'JRFXUAMQNBLHGTVCZYPIWKDSOE',
       'CAMOWSFXGIBKNDVRPHZEJULTQY', 'FUYILXREJTDNPSWVOKCBHQZMGA', 'KNQPFIYTJMHLSUBDXWREACZOVG',
       'ADLJKCNYUTVHMFIZOSQRXBPEGW', 'XVPCJHQIOBULMSATYDKNZRWGFE', 'GEHFWIQSBMLCYJDRNVZXTAPUOK',
       'MLVUDAKGBHYTZQCSEXFPNWROJI', 'GMFXBOSVEKWTRUHYZCAPDINLQJ', 'VDMLSBEOIRXCJZKWHPNQTFAUGY',
       'PVJDOERNLZUBQHCFGYSAWTXIKM', 'SYTBRJAVDXUWMKGINCHZPEFLQO', 'YIFUHOKDGTALNSCMRVEJWBXZPQ']
exp_c = ['CRIPTOGRAFIA', 'GNDOZAQZLLEI', 'KHYCGTPWWWSZ', 'QOLADSCJORAS', 'PDVGIDEKRHQY', 'TSKWHKDBCZFO', 'SEJDVBSTUJYL',
         'ILEJCNYATQKU', 'YUQSLGJUHYTG', 'HMRUSVNHYNUN', 'FBBFFZWLGSPM', 'NJCBKMXFVDWC', 'ZPFIAPKYEIVH', 'JYTRJQBSKMLB',
         'UIAHEUMGNPCR', 'EGMXUJLCXBMD', 'VQWNWXRVJKGQ', 'DXXKPFZISEJK', 'XKZMMETPZGRW', 'AAPVXRVEFXXX', 'WVSYBHFXPUOT',
         'OZHTOIHQDCDF', 'RCOLQCUMIONV', 'MWNERLAOBAHJ', 'LFUQYWINMTBE', 'BTGZNYODQVZP']
test_case_2("2.1", key, "CRIPTOGRAFIA", exp_c)

key = ['SEZRYUJAWKMOTGVPINCBQXFLHD', 'VHXBCNPQFMJGEDIKOYWTRSZLUA', 'BJFZIVLEMXAPRUYHDSWTGOKCNQ',
       'IYFKRPHCMSTZEVADBQULWGJXNO', 'EIHXPFYLGOVJQRCDUAMNTBWKSZ', 'ZCFVJPKIODQGAWLXMUETRSYBNH',
       'DZUEHCGONSAFPTXBWYLVJMRKQI', 'HNMCJSYLOBTUWXIKGQPVADZRFE', 'KEACIYSLHQVMTXJOBNZWPGDURF',
       'JSYZQDNXHWTUMVRBOAFCIGEPKL', 'OCWVEFQNLKAYUBJZSTGPXIHMRD', 'LFUNTPAOGJWXESBKZQHMDCYRVI',
       'FRKHUYLGNQMEITACDVXZPBOWJS', 'QHJOMYZARWXKNBSLEVDFIPUGTC', 'DSOCYMTIAZRGKUPXFQJVHEWNLB',
       'ZOQXIBWVAFJSCLNRGMDPEHTKUY', 'RNGWTLOUSXPJCFIMHAVEBKYDQZ', 'BIKQXTJOAMLFYWRUSNZPCVHGDE',
       'CPGARKBNFMJSXVLEUQDZTYOHWI', 'NOHGTEYAKCPDVJLZBWRIQMFXSU', 'SNTPOUJZFLIGBRCHAVWYMXDQEK',
       'UDNMQWAXZBILROFHVYPCKJESTG', 'RXTCJLIHEKSZFYMVWPDAQBUNOG', 'KQTRMCIDPNOZHFUEVJAYBLWGSX',
       'HWYSZECFGBNKLXOTJUAQDRIPVM', 'QRZVUPGNKJMOIXHEDAFTBCSYLW', 'IMGXAVOWFKHNSZDLQPCBEYRUTJ',
       'IYWLTPBDAQJURHOCXZFSGMEVNK', 'NHSYIDXJPRBUZGEKFAOTMWVLCQ', 'LGQIAYMOWECURDXTJZPHNBVKFS',
       'CAPUEIBOXQTLVZKHSGWNMFYJRD', 'PBJAFZHSVXNIGMYDOEKCRUQLTW', 'BUEODYZTSRIKAMGQCWVFLHJNXP',
       'PRAZYNBUDEVWCQHTFSMJXKIOLG', 'YLOAGZFEKIRVPCXUSBDWNMJHQT', 'QXGBFIMSOVYKPWTDCJUNAHZREL']
exp_c = ['SECURITY', 'EDNLCOXL', 'ZIQWDDBO', 'RKBGUQWB', 'YOJJAGYT', 'UYFXMALU', 'JWZNNWVW', 'ATIOTLJX', 'WRVIBXMI',
         'KSLYWMRK', 'MZEFKUKG', 'OLMKSEQQ', 'TUXRZTIP', 'GAAPERDV', 'VVPHISZA', 'PHRCHYUD', 'IXUMXBEZ', 'NBYSPNHR',
         'CCHTFHCF', 'BNDZYZGE', 'QPSELCOH', 'XQWVGFNN', 'FFTAOVSM', 'LMGDVJAC', 'HJOBJPFJ', 'DGKQQKPS']
test_case_2("2.2", key, "SECURITY", exp_c)

key = ['SEZRYUJAWKMOTGVPINCBQXFLHD', 'VHXBCNPQFMJGEDIKOYWTRSZLUA', 'BJFZIVLEMXAPRUYHDSWTGOKCNQ',
       'IYFKRPHCMSTZEVADBQULWGJXNO', 'EIHXPFYLGOVJQRCDUAMNTBWKSZ', 'ZCFVJPKIODQGAWLXMUETRSYBNH',
       'DZUEHCGONSAFPTXBWYLVJMRKQI', 'HNMCJSYLOBTUWXIKGQPVADZRFE', 'KEACIYSLHQVMTXJOBNZWPGDURF',
       'JSYZQDNXHWTUMVRBOAFCIGEPKL', 'OCWVEFQNLKAYUBJZSTGPXIHMRD', 'LFUNTPAOGJWXESBKZQHMDCYRVI',
       'FRKHUYLGNQMEITACDVXZPBOWJS', 'QHJOMYZARWXKNBSLEVDFIPUGTC', 'DSOCYMTIAZRGKUPXFQJVHEWNLB',
       'ZOQXIBWVAFJSCLNRGMDPEHTKUY', 'RNGWTLOUSXPJCFIMHAVEBKYDQZ', 'BIKQXTJOAMLFYWRUSNZPCVHGDE',
       'CPGARKBNFMJSXVLEUQDZTYOHWI', 'NOHGTEYAKCPDVJLZBWRIQMFXSU', 'SNTPOUJZFLIGBRCHAVWYMXDQEK',
       'UDNMQWAXZBILROFHVYPCKJESTG', 'RXTCJLIHEKSZFYMVWPDAQBUNOG', 'KQTRMCIDPNOZHFUEVJAYBLWGSX',
       'HWYSZECFGBNKLXOTJUAQDRIPVM', 'QRZVUPGNKJMOIXHEDAFTBCSYLW', 'IMGXAVOWFKHNSZDLQPCBEYRUTJ',
       'IYWLTPBDAQJURHOCXZFSGMEVNK', 'NHSYIDXJPRBUZGEKFAOTMWVLCQ', 'LGQIAYMOWECURDXTJZPHNBVKFS',
       'CAPUEIBOXQTLVZKHSGWNMFYJRD', 'PBJAFZHSVXNIGMYDOEKCRUQLTW', 'BUEODYZTSRIKAMGQCWVFLHJNXP',
       'PRAZYNBUDEVWCQHTFSMJXKIOLG', 'YLOAGZFEKIRVPCXUSBDWNMJHQT', 'QXGBFIMSOVYKPWTDCJUNAHZREL']
exp_c = ['TURING', 'GAUYTA', 'VVYFBW', 'PHHKWL', 'IXDRKX', 'NBSPSM', 'CCWHZU', 'BNTCEE', 'QPGMIT', 'XQOSHR', 'FFKTXS',
         'LMCZPY', 'HJNEFB', 'DGQVYN', 'SEBALH', 'EDJDGZ', 'ZIFBOC', 'RKZQVF', 'YOIUJV', 'UYVLQJ', 'JWLWRP', 'ATEGCK',
         'WRMJDI', 'KSXXUO', 'MZANAD', 'OLPOMQ']
test_case_2("2.3", key, "TURING", exp_c)

key = ['IQKWSBXALYPUDECMTROGNHFJZV', 'NWPYMFOQIJHDEAKBVTSLXGUZCR', 'DYVFXQJMKSWNABLOIPHRTECUGZ',
       'BMCHJUKWZXNVSPLRYDTOIFEAGQ', 'UACBIOFZRNWQPHTMGSVEKXLDJY', 'DZOXQAIUTBPKFESWRLVJGCNYHM',
       'DYITHOSQJFRGCAMUVKBPLXENZW', 'CNPXFGIWTOHUSEMLKZRABYJVDQ', 'OJZBFDATCINGHMSEVWQKLYRUXP',
       'TFMAWXCQLDZBGHYJIPNOURKEVS', 'LWTAXVMFQHODRNBEJUKPSZYCGI', 'AOQBPISFDZJMGLHKXTNYUWVREC',
       'KYBCIGAENPFMDQVTRJOWXZHSUL', 'KHTUFBQAOXWJVCRSEGNMZPIYLD', 'YTANCXOJVFIGDHULPSMQZKBWER',
       'UCJNDYXPKMBZSHATRQLEWFOGVI', 'LSGFRTWKAINOCJDUMZHQXBYEVP', 'CMUPFAGHRBESKXYOINTDJWLVQZ',
       'LVMTSGKBOJDCHUFRPEYNZAWXIQ', 'AVMLOIWESYZXRDQFJGUTHNPBKC', 'MDAKBQUCZVFXLJPSTNHEWIRGYO',
       'TCSQIAZKXGHPNMVYRODWJFLBEU', 'DSJAEYUWCKMZTIGHVXOPNRLBFQ', 'UZSYECXWHJMPIKTGBOLANFDQRV',
       'OLGQURAXESVFDPITWCMYZHKNBJ', 'IGLPSAJXCVFKMWNTOQRBEZHDYU', 'ZSXHATMEKVDBCGUYPFOJWNIRQL',
       'CWMXYGTKNEJFHZQABPOVDIRSUL', 'SPEJTIOBGVUKNFAZMCWHLYRDQX', 'CQWKHTYXLEGNIAMFBVRJPZSOUD',
       'FHZPCXDLAYVBEJKIMQTORGNWSU', 'SVMLAWIRZEXJGUNHOBCTQKFYDP', 'VCESOWMGBUFZQKDJIYXANRTHPL',
       'LIFXNUVKCYDSMGEHTOJBPRWZQA', 'DINXPWGYOEFJUZVLTACQBMRHKS', 'KHMYUBVDTJQEIRSAZNWLGPOFXC']
exp_c = ['ATTACK', 'LSEGBF', 'YLCQIE', 'PXUBOS', 'UGGMFW', 'DUZCZR', 'EZDHRL', 'CCYJNV', 'MRVUWJ', 'TNFKQG', 'RWXWPC',
         'OPQZHN', 'GYJXTY', 'NMMNMH', 'HFKVGM', 'FOSSSD', 'JQWPVZ', 'ZINLEO', 'VJARKX', 'IHBYXQ', 'QDLDLA', 'KEOTDI',
         'WAIOJU', 'SKPIYT', 'BBHFUB', 'XVREAP']
test_case_2("2.4", key, "ATTACK", exp_c)

key = ['DY6U7HJRN15LS8VET2PIFZWXAO39QGC4BK0M', '0567B4T38JUDE12GKNYSOZHRX9IVMQFPCALW',
       'XW2ATYK4GB7DIVHJL59ZONQ1F8PS0UMC36ER', 'BZGENPKI2584WRJC3MH7S6TYD9VXLUAF1O0Q',
       'I95ZDPOYJFRXQA8V0W7426HNBELSUC3GKT1M', 'VPZS17TL0B59OECRWHYAMX48UGQ2KDF63JIN',
       'P63BSJKEO5L20INYCMDVUTQAZ7W48FXG1R9H', 'XZN8GTY5H7VWOB6AKUQ1EL0FRSI43MC2D9JP',
       '7GOI3VM1SZU2PHRAQYFD58KCX6B40LENW9TJ', 'JD0Z7IT1PV2F4Y3WSQ5AULHOC9RKXGB8MNE6']
exp_c = ['CRIPTO', '4XVK1E', 'B9HIMC', 'KIJ2IR', '0VL59W', 'MM585H', 'DQ94ZY', 'YFZWDA', '6PORPM', 'UCNJOX', '7AQCY4',
         'HL13J8', 'JWFMFU', 'R08HRG', 'N5P7XQ', '16SSQ2', '5706AK', 'LBUT8D', 'S4MYVF', '8TCD06', 'V339W3', 'E86V7J',
         'TJEX4I', '2URL2N', 'PDXU6V', 'IEWAHP', 'F12FNZ', 'Z2A1BS', 'WGTOE1', 'XKY0L7', 'ANKQST', 'OY4BUL', '3SGZC0',
         '9OBG3B', 'QZ7EG5', 'GHDNK9']
test_case_2("2.5", key, "CRIPTO", exp_c)

####################################################################################
# TEST CASES EXERCISE 3
####################################################################################

def test_case_3(name, key, ciphertexts, exp_m):
    print "Test", name + ":", all([exp_m == UOC_jeff_decipher(key, c) for c in ciphertexts])


def test_case_3_2(name, key, ciphertext, exp_m):
    candidates = UOC_jeff_decipher(key, ciphertext)
    print "Test", name + ":", sorted(candidates) == sorted(exp_m)


key = ['AWORMLBCGKQPTSIYHFNZJUEVDX', 'DSELUMBJPYIGQXKAVZCWFTRNHO', 'GIDYLVKJEQRBCFTAMWXZPSHONU',
       'KMVYTLEQZPOCAGWDJSUFBIRHXN', 'WPMXBOQRYNTZGDIHVCLSFKAJEU', 'QUJXFERHICLWYOATSDKBNGVZMP',
       'FHUAIOGQPCEDSYJNWXKBMLRZTV', 'XQMONDRZWJKBTAUHLFYSGCVIPE', 'ORCUTHYGVEKNXJSZFPDIBMQALW',
       'GXUCOATVFLWRHZJQYNSDIMPBKE', 'XODNHBZIESAQFYKTUPWVLCMGJR', 'KWXTFVJEPAIZSYOLUGNMCHBRDQ',
       'PDUMKASBHJTLYNVQZEXFCIGORW', 'WDEKIYHQSCANGFBXTRLZPUVOMJ', 'MSTGCHIDVPOKQRLWBXZYJAENFU',
       'OFGMKIADHUTSCELRPVQNJYZXWB', 'JEZQSTWKYPFBAXIRCNUOHDLMVG', 'KCGUPFRTEJQXSHDMAIYVNLBZWO',
       'CQBIKAGMELWZPDNFRJUHSVOXTY', 'ALJPTIFWNCSHVUOYXQMBEDZKGR', 'DFEKPCQMBLAIGYJTXZRUSONVWH',
       'NAHCOJFGLYRSPDBVXEZMUIWQKT', 'TXKCMJPZHYQDGULIFBSOREANVW', 'JRFXUAMQNBLHGTVCZYPIWKDSOE',
       'CAMOWSFXGIBKNDVRPHZEJULTQY', 'FUYILXREJTDNPSWVOKCBHQZMGA', 'KNQPFIYTJMHLSUBDXWREACZOVG',
       'ADLJKCNYUTVHMFIZOSQRXBPEGW', 'XVPCJHQIOBULMSATYDKNZRWGFE', 'GEHFWIQSBMLCYJDRNVZXTAPUOK',
       'MLVUDAKGBHYTZQCSEXFPNWROJI', 'GMFXBOSVEKWTRUHYZCAPDINLQJ', 'VDMLSBEOIRXCJZKWHPNQTFAUGY',
       'PVJDOERNLZUBQHCFGYSAWTXIKM', 'SYTBRJAVDXUWMKGINCHZPEFLQO', 'YIFUHOKDGTALNSCMRVEJWBXZPQ']
ciphertexts = ['CRIPTOGRAFIA', 'GNDOZAQZLLEI', 'KHYCGTPWWWSZ', 'QOLADSCJORAS', 'PDVGIDEKRHQY', 'TSKWHKDBCZFO',
               'SEJDVBSTUJYL', 'ILEJCNYATQKU', 'YUQSLGJUHYTG', 'HMRUSVNHYNUN', 'FBBFFZWLGSPM', 'NJCBKMXFVDWC',
               'ZPFIAPKYEIVH', 'JYTRJQBSKMLB', 'UIAHEUMGNPCR', 'EGMXUJLCXBMD', 'VQWNWXRVJKGQ', 'DXXKPFZISEJK',
               'XKZMMETPZGRW', 'AAPVXRVEFXXX', 'WVSYBHFXPUOT', 'OZHTOIHQDCDF', 'RCOLQCUMIONV', 'MWNERLAOBAHJ',
               'LFUQYWINMTBE', 'BTGZNYODQVZP']
test_case_3("3.1", key, ciphertexts, "CRIPTOGRAFIA")

key = ['SEZRYUJAWKMOTGVPINCBQXFLHD', 'VHXBCNPQFMJGEDIKOYWTRSZLUA', 'BJFZIVLEMXAPRUYHDSWTGOKCNQ',
       'IYFKRPHCMSTZEVADBQULWGJXNO', 'EIHXPFYLGOVJQRCDUAMNTBWKSZ', 'ZCFVJPKIODQGAWLXMUETRSYBNH',
       'DZUEHCGONSAFPTXBWYLVJMRKQI', 'HNMCJSYLOBTUWXIKGQPVADZRFE', 'KEACIYSLHQVMTXJOBNZWPGDURF',
       'JSYZQDNXHWTUMVRBOAFCIGEPKL', 'OCWVEFQNLKAYUBJZSTGPXIHMRD', 'LFUNTPAOGJWXESBKZQHMDCYRVI',
       'FRKHUYLGNQMEITACDVXZPBOWJS', 'QHJOMYZARWXKNBSLEVDFIPUGTC', 'DSOCYMTIAZRGKUPXFQJVHEWNLB',
       'ZOQXIBWVAFJSCLNRGMDPEHTKUY', 'RNGWTLOUSXPJCFIMHAVEBKYDQZ', 'BIKQXTJOAMLFYWRUSNZPCVHGDE',
       'CPGARKBNFMJSXVLEUQDZTYOHWI', 'NOHGTEYAKCPDVJLZBWRIQMFXSU', 'SNTPOUJZFLIGBRCHAVWYMXDQEK',
       'UDNMQWAXZBILROFHVYPCKJESTG', 'RXTCJLIHEKSZFYMVWPDAQBUNOG', 'KQTRMCIDPNOZHFUEVJAYBLWGSX',
       'HWYSZECFGBNKLXOTJUAQDRIPVM', 'QRZVUPGNKJMOIXHEDAFTBCSYLW', 'IMGXAVOWFKHNSZDLQPCBEYRUTJ',
       'IYWLTPBDAQJURHOCXZFSGMEVNK', 'NHSYIDXJPRBUZGEKFAOTMWVLCQ', 'LGQIAYMOWECURDXTJZPHNBVKFS',
       'CAPUEIBOXQTLVZKHSGWNMFYJRD', 'PBJAFZHSVXNIGMYDOEKCRUQLTW', 'BUEODYZTSRIKAMGQCWVFLHJNXP',
       'PRAZYNBUDEVWCQHTFSMJXKIOLG', 'YLOAGZFEKIRVPCXUSBDWNMJHQT', 'QXGBFIMSOVYKPWTDCJUNAHZREL']
ciphertexts = ['SECURITY', 'EDNLCOXL', 'ZIQWDDBO', 'RKBGUQWB', 'YOJJAGYT', 'UYFXMALU', 'JWZNNWVW', 'ATIOTLJX',
               'WRVIBXMI', 'KSLYWMRK', 'MZEFKUKG', 'OLMKSEQQ', 'TUXRZTIP', 'GAAPERDV', 'VVPHISZA', 'PHRCHYUD',
               'IXUMXBEZ', 'NBYSPNHR', 'CCHTFHCF', 'BNDZYZGE', 'QPSELCOH', 'XQWVGFNN', 'FFTAOVSM', 'LMGDVJAC',
               'HJOBJPFJ', 'DGKQQKPS']
test_case_3("3.2", key, ciphertexts, "SECURITY")

key = ['SEZRYUJAWKMOTGVPINCBQXFLHD', 'VHXBCNPQFMJGEDIKOYWTRSZLUA', 'BJFZIVLEMXAPRUYHDSWTGOKCNQ',
       'IYFKRPHCMSTZEVADBQULWGJXNO', 'EIHXPFYLGOVJQRCDUAMNTBWKSZ', 'ZCFVJPKIODQGAWLXMUETRSYBNH',
       'DZUEHCGONSAFPTXBWYLVJMRKQI', 'HNMCJSYLOBTUWXIKGQPVADZRFE', 'KEACIYSLHQVMTXJOBNZWPGDURF',
       'JSYZQDNXHWTUMVRBOAFCIGEPKL', 'OCWVEFQNLKAYUBJZSTGPXIHMRD', 'LFUNTPAOGJWXESBKZQHMDCYRVI',
       'FRKHUYLGNQMEITACDVXZPBOWJS', 'QHJOMYZARWXKNBSLEVDFIPUGTC', 'DSOCYMTIAZRGKUPXFQJVHEWNLB',
       'ZOQXIBWVAFJSCLNRGMDPEHTKUY', 'RNGWTLOUSXPJCFIMHAVEBKYDQZ', 'BIKQXTJOAMLFYWRUSNZPCVHGDE',
       'CPGARKBNFMJSXVLEUQDZTYOHWI', 'NOHGTEYAKCPDVJLZBWRIQMFXSU', 'SNTPOUJZFLIGBRCHAVWYMXDQEK',
       'UDNMQWAXZBILROFHVYPCKJESTG', 'RXTCJLIHEKSZFYMVWPDAQBUNOG', 'KQTRMCIDPNOZHFUEVJAYBLWGSX',
       'HWYSZECFGBNKLXOTJUAQDRIPVM', 'QRZVUPGNKJMOIXHEDAFTBCSYLW', 'IMGXAVOWFKHNSZDLQPCBEYRUTJ',
       'IYWLTPBDAQJURHOCXZFSGMEVNK', 'NHSYIDXJPRBUZGEKFAOTMWVLCQ', 'LGQIAYMOWECURDXTJZPHNBVKFS',
       'CAPUEIBOXQTLVZKHSGWNMFYJRD', 'PBJAFZHSVXNIGMYDOEKCRUQLTW', 'BUEODYZTSRIKAMGQCWVFLHJNXP',
       'PRAZYNBUDEVWCQHTFSMJXKIOLG', 'YLOAGZFEKIRVPCXUSBDWNMJHQT', 'QXGBFIMSOVYKPWTDCJUNAHZREL']
ciphertexts = ['TURING', 'GAUYTA', 'VVYFBW', 'PHHKWL', 'IXDRKX', 'NBSPSM', 'CCWHZU', 'BNTCEE', 'QPGMIT', 'XQOSHR',
               'FFKTXS', 'LMCZPY', 'HJNEFB', 'DGQVYN', 'SEBALH', 'EDJDGZ', 'ZIFBOC', 'RKZQVF', 'YOIUJV', 'UYVLQJ',
               'JWLWRP', 'ATEGCK', 'WRMJDI', 'KSXXUO', 'MZANAD', 'OLPOMQ']
test_case_3("3.3", key, ciphertexts, "TURING")

key = ['IQKWSBXALYPUDECMTROGNHFJZV', 'NWPYMFOQIJHDEAKBVTSLXGUZCR', 'DYVFXQJMKSWNABLOIPHRTECUGZ',
       'BMCHJUKWZXNVSPLRYDTOIFEAGQ', 'UACBIOFZRNWQPHTMGSVEKXLDJY', 'DZOXQAIUTBPKFESWRLVJGCNYHM',
       'DYITHOSQJFRGCAMUVKBPLXENZW', 'CNPXFGIWTOHUSEMLKZRABYJVDQ', 'OJZBFDATCINGHMSEVWQKLYRUXP',
       'TFMAWXCQLDZBGHYJIPNOURKEVS', 'LWTAXVMFQHODRNBEJUKPSZYCGI', 'AOQBPISFDZJMGLHKXTNYUWVREC',
       'KYBCIGAENPFMDQVTRJOWXZHSUL', 'KHTUFBQAOXWJVCRSEGNMZPIYLD', 'YTANCXOJVFIGDHULPSMQZKBWER',
       'UCJNDYXPKMBZSHATRQLEWFOGVI', 'LSGFRTWKAINOCJDUMZHQXBYEVP', 'CMUPFAGHRBESKXYOINTDJWLVQZ',
       'LVMTSGKBOJDCHUFRPEYNZAWXIQ', 'AVMLOIWESYZXRDQFJGUTHNPBKC', 'MDAKBQUCZVFXLJPSTNHEWIRGYO',
       'TCSQIAZKXGHPNMVYRODWJFLBEU', 'DSJAEYUWCKMZTIGHVXOPNRLBFQ', 'UZSYECXWHJMPIKTGBOLANFDQRV',
       'OLGQURAXESVFDPITWCMYZHKNBJ', 'IGLPSAJXCVFKMWNTOQRBEZHDYU', 'ZSXHATMEKVDBCGUYPFOJWNIRQL',
       'CWMXYGTKNEJFHZQABPOVDIRSUL', 'SPEJTIOBGVUKNFAZMCWHLYRDQX', 'CQWKHTYXLEGNIAMFBVRJPZSOUD',
       'FHZPCXDLAYVBEJKIMQTORGNWSU', 'SVMLAWIRZEXJGUNHOBCTQKFYDP', 'VCESOWMGBUFZQKDJIYXANRTHPL',
       'LIFXNUVKCYDSMGEHTOJBPRWZQA', 'DINXPWGYOEFJUZVLTACQBMRHKS', 'KHMYUBVDTJQEIRSAZNWLGPOFXC']
ciphertexts = ['ATTACK', 'LSEGBF', 'YLCQIE', 'PXUBOS', 'UGGMFW', 'DUZCZR', 'EZDHRL', 'CCYJNV', 'MRVUWJ', 'TNFKQG',
               'RWXWPC', 'OPQZHN', 'GYJXTY', 'NMMNMH', 'HFKVGM', 'FOSSSD', 'JQWPVZ', 'ZINLEO', 'VJARKX', 'IHBYXQ',
               'QDLDLA', 'KEOTDI', 'WAIOJU', 'SKPIYT', 'BBHFUB', 'XVREAP']
test_case_3("3.4", key, ciphertexts, "ATTACK")

key = ['DY6U7HJRN15LS8VET2PIFZWXAO39QGC4BK0M', '0567B4T38JUDE12GKNYSOZHRX9IVMQFPCALW',
       'XW2ATYK4GB7DIVHJL59ZONQ1F8PS0UMC36ER', 'BZGENPKI2584WRJC3MH7S6TYD9VXLUAF1O0Q',
       'I95ZDPOYJFRXQA8V0W7426HNBELSUC3GKT1M', 'VPZS17TL0B59OECRWHYAMX48UGQ2KDF63JIN',
       'P63BSJKEO5L20INYCMDVUTQAZ7W48FXG1R9H', 'XZN8GTY5H7VWOB6AKUQ1EL0FRSI43MC2D9JP',
       '7GOI3VM1SZU2PHRAQYFD58KCX6B40LENW9TJ', 'JD0Z7IT1PV2F4Y3WSQ5AULHOC9RKXGB8MNE6']
ciphertexts = ['CRIPTO', '4XVK1E', 'B9HIMC', 'KIJ2IR', '0VL59W', 'MM585H', 'DQ94ZY', 'YFZWDA', '6PORPM', 'UCNJOX',
               '7AQCY4', 'HL13J8', 'JWFMFU', 'R08HRG', 'N5P7XQ', '16SSQ2', '5706AK', 'LBUT8D', 'S4MYVF', '8TCD06',
               'V339W3', 'E86V7J', 'TJEX4I', '2URL2N', 'PDXU6V', 'IEWAHP', 'F12FNZ', 'Z2A1BS', 'WGTOE1', 'XKY0L7',
               'ANKQST', 'OY4BUL', '3SGZC0', '9OBG3B', 'QZ7EG5', 'GHDNK9']
test_case_3("3.5", key, ciphertexts, "CRIPTO")

key = ['IQKWSBXALYPUDECMTROGNHFJZV', 'NWPYMFOQIJHDEAKBVTSLXGUZCR', 'DYVFXQJMKSWNABLOIPHRTECUGZ',
       'BMCHJUKWZXNVSPLRYDTOIFEAGQ', 'UACBIOFZRNWQPHTMGSVEKXLDJY', 'DZOXQAIUTBPKFESWRLVJGCNYHM',
       'DYITHOSQJFRGCAMUVKBPLXENZW', 'CNPXFGIWTOHUSEMLKZRABYJVDQ', 'OJZBFDATCINGHMSEVWQKLYRUXP',
       'TFMAWXCQLDZBGHYJIPNOURKEVS', 'LWTAXVMFQHODRNBEJUKPSZYCGI', 'AOQBPISFDZJMGLHKXTNYUWVREC',
       'KYBCIGAENPFMDQVTRJOWXZHSUL', 'KHTUFBQAOXWJVCRSEGNMZPIYLD', 'YTANCXOJVFIGDHULPSMQZKBWER',
       'UCJNDYXPKMBZSHATRQLEWFOGVI', 'LSGFRTWKAINOCJDUMZHQXBYEVP', 'CMUPFAGHRBESKXYOINTDJWLVQZ',
       'LVMTSGKBOJDCHUFRPEYNZAWXIQ', 'AVMLOIWESYZXRDQFJGUTHNPBKC', 'MDAKBQUCZVFXLJPSTNHEWIRGYO',
       'TCSQIAZKXGHPNMVYRODWJFLBEU', 'DSJAEYUWCKMZTIGHVXOPNRLBFQ', 'UZSYECXWHJMPIKTGBOLANFDQRV',
       'OLGQURAXESVFDPITWCMYZHKNBJ', 'IGLPSAJXCVFKMWNTOQRBEZHDYU', 'ZSXHATMEKVDBCGUYPFOJWNIRQL',
       'CWMXYGTKNEJFHZQABPOVDIRSUL', 'SPEJTIOBGVUKNFAZMCWHLYRDQX', 'CQWKHTYXLEGNIAMFBVRJPZSOUD',
       'FHZPCXDLAYVBEJKIMQTORGNWSU', 'SVMLAWIRZEXJGUNHOBCTQKFYDP', 'VCESOWMGBUFZQKDJIYXANRTHPL',
       'LIFXNUVKCYDSMGEHTOJBPRWZQA', 'DINXPWGYOEFJUZVLTACQBMRHKS', 'KHMYUBVDTJQEIRSAZNWLGPOFXC']
result = ['GYJXTYMEU', 'NMMNMHUMX', 'HFKVGMVLP', 'FOSSSDKKO', 'JQWPVZBZJ', 'ZINLEOPRZ', 'VJARKXLAB', 'IHBYXQXBF',
          'QDLDLAEYD', 'KEOTDINJA', 'WAIOJUZVT', 'SKPIYTWDC', 'BBHFUBDQI', 'XVREAPYCN', 'ATTACKING', 'LSEGBFTPH',
          'YLCQIEHXM', 'PXUBOSOFS', 'UGGMFWSGE', 'DUZCZRQIV', 'EZDHRLJWW', 'CCYJNVFTQ', 'MRVUWJROK', 'TNFKQGGHL',
          'RWXWPCCUY', 'OPQZHNASR']
test_case_3_2("3.5", key, "GYJXTYMEU", result)
test_case_3_2("3.6", key, "FOSSSDKKO", result)