from Crypto.Util.number import  * 
import gmpy2
from pwn import *

# f = connect("193.148.168.30", 5668)
# f.recvuntil(b"Select Option: ")
# f.sen


def crt(list_a, list_m):
    """
    Reference: https://crypto.stanford.edu/pbc/notes/numbertheory/crt.html
    Returns the output after computing Chinese Remainder Theorem on

    x = a_1 mod m_1
    x = a_2 mod m_2
    ...
    x = a_n mod m_n

    input parameter list_a = [a_1, a_2, ..., a_n]
    input parameter list_m = [m_1, m_2, ..., m_n]

    Returns -1 if the operation is unsuccessful due to some exceptions
    """
    try:
        assert len(list_a) == len(list_m)
    except:
        print ("[+] Length of list_a should be equal to length of list_m")
        return -1
    for i in range(len(list_m)):
        for j in range(len(list_m)):
            if GCD(list_m[i], list_m[j])!= 1 and i!=j:
                print ("[+] Moduli should be pairwise co-prime")
                return -1
    M = 1
    for i in list_m:
        M *= i
    list_b = [M/i for i in list_m]
    assert len(list_b) == len(list_m)
    try:
        list_b_inv = [int(gmpy2.invert(list_b[i], list_m[i])) for i in range(len(list_m))]
    except:
        print( "[+] Encountered an unusual error while calculating inverse using gmpy2.invert()")
        return -1
    x = 0
    for i in range(len(list_m)):
        x += list_a[i]*list_b[i]*list_b_inv[i]
    return x % M


def test_crt():
    """
    Checking the validity and consistency of CRT function
    """
    list_a = [[2, 3], [1, 2, 3, 4], [6, 4]]
    list_m = [[5, 7], [5, 7, 9, 11], [7, 8]]
    soln_list = [17, 1731, 20]
    try:
        for i in range(len(list_a)):
            assert crt(list_a[i], list_m[i]) == soln_list[i]
    except:
        print ("[+] CRT function broken. Check the function again!")


def hastad_unpadded(ct_list, mod_list, e):
    """
    Implementing Hastad's Broadcast Attack
    """
    m_expo = crt(ct_list, mod_list)
    if m_expo != -1:
        eth_root = gmpy2.iroot(m_expo, e)
        if eth_root[1] == False:
            print ("[+] Cannot calculate e'th root!")
            return -1
        elif eth_root[1] == True:
            return long_to_bytes(eth_root)
    else:
        print( "[+] Cannot calculate CRT")
        return -1

# test_crt()


n1 = 14681971706431067153190908197482100053580981827276053487047823496171074050719515870823510425195845991000152676656736056991507687609989170668384668390835903259829282252356208047524099685436195389423866601330082297048224416925778449965866751442701645217979747986100395724703170930920517906338141107145641448380520503402711579089625426717351549397318230139722021180219380083103232922886177093817308366281182864752591631180388928331001834196469636954038864536837910723362933053798152954195809822742305522516789258785814932567757705169768160927708170891076876779312959802477151808471770263707773321325575645515165898669649
flag1 = 9849670734672925038499438713548164133030913784166831644202795263632676862255012389065346938486602981420604857288239144088927151120505679678297157684132228369324662575923508768769991116282504074231343634166586339651581538193730285943665611951996899740599887804316478437699108462697556097715847320586732445779622754682772898696848269254071663540939662923470949158982981727009439303325107112174504824897327649034191077171755263558509765823781576167133336379296435171700423412349244758819176711608848669196265850976038589370851870319049742318697880094510283366147674481343232179524660561871398978921986855189646044574361

n2 = 14985924656857076406926832780042873838078701366427109987512395367114726499361043902356432625726088552128825013617476073973872697185537551195240277644941019111727986236137932856764570237996398142561495838523869608166967464547168019601682557199580968646348928927877793983537444328443391400026439009291374206451072264444348815983423349991194186724175881083953109107335529577386172760314685785473415890445501171178442732186331610018904656725179738244495374362782969221595032538455437677251065402577976686185093566560769938875613725200005989313825510373284953762871081226777989739953858977390964526975437561360272466022981
flag2 = 13318741140749350920813159455330692248517316020834008884393832083039467870984280938012864721238652445183044375656647712726856576807414715150638873668218290322082843461170582342614912577772154597473919557959778801447669929827127593150390351168924307484901965355423225723319806525222710133445103781577910389191354257494625562812081662665601918639561284685576396809100496131979941984982069527027520535641641048951371348897926140772866332638689626453502204759507095286613865393172904785598497604924606514927685290309571592106110031217468699838893203383255404893402976805198861524007284321693468370933782845053139687617722

n3 = 10219590051575402747018912736139537038536473382356005598498814978820384118936091447096017269804556743742486184918083110655883980259530275478404471864985514721941571442906994640642779743816644843415637689810346381054505492528538543152778625229116937775442292707878253842211041681730870214407956927936013602591375339505603697804407749575217941155308035086786038756659190331730391039239574078810660937958362142826535895689479023141001478772016320711105609873043703761595201472322003757629543751806566616252182169814643464740022277496484738426036893126263836722072112835158819542226996208124243866939619995510682354896349
flag3 = 8559259827385488458775344528462871229368313647327732329767295810831250238131676789829420841020366574622545822978467595804395310187359636373496939514952291314749416368626154268526598865547105815364556498755852468287454920119790414495786602708650547452782610752083150338163388725146008822583935771418632873216977195514160954174288617320567743515200402353041133350438632184485698187591623801394719790586462080594135983825723959801022564906195639300431356354568855765477059117257374861883878468859408199390013460341032975310154312962317094913259699571872246212548249205868328019211484936657859845467527901901027815017112

n4 = 22088075623449089379001213109232975483869686514759852115003772871942015448723282530709497336595248669695579774761119394064723166513766053526105035482014071145239697343211473112249099307474099233311517657238595928939911781494032929952637998052684220222164334179640848741324674404031384545236178362157778876477343402517453555030154892219887908616011396118767741568421596468107966595294655725288481670025528486589709806324581588359779737490446205022362925118141883126459996056488792995799199029307774208087057127920343452477039410412817320247886014914629645792698375176329893338845022989695058003441555758526612415285327
flag4 = 11401558704184287914454482531290269934891504839657804788655179297140481762076836037153938775940984410205790304857010666202358921148958665286951247941559880032324475070499125463075230658239921048424425049371586168508146436587283873656231514373830611483877400951437352537385347572931195131827596374317756334608538559184090746463254995043635656651727119156857144365985294687780946833127826394049620157145360747166457755166217425065160607898847540451411964408375229580188707384944347923022212486057201975821159812175875384587611324008116289052560402639405577003246335163865957991529233404455890653056992554073271330570710

n5 = 15148040034381450453147849432794161999907659934871130183525831756959468384818805963913219577151999291112918876702061174875115285962813916839991252767686780611811896584885306624715091799869849708192282345040201501673562676900297445536409997640531830571440947716325986118277903426815300960372264861537457878047146824982590635538522464642948462187958642346962599715851244015130487028864929013111800261353139507719886448045619789914327785508545128516601952807973630875496915695948016433104533427019094947838199695227073868965031098499465120124704026941355371459671621106892413151984748497269471883728179668742724021451979
flag5 = 11053901288578730224006245508591428224258427085784425377145444715036963790653382020864733752423896141353817783790834119094104594944995393087111114429052085037711598634645948588128711987629298522309002927179826692614362962201588438005417180342274538815807778699028696304932767233040893595862667867245504534352496654346065861295706293370384051213050859112689351701960264182231959100079629743231261422237192949196557604430588703623449602223097092919566760023475514691859197119913739950057800632720230920247833617433443970061518663558424192639927750743754117806727721818895027961421100241809967439175501818099973820397277

n6 = 12775302317257437438534905745957432025177874544743277572034494141804978164282994437889430659381552915273624621202529445956660541297407222115837024296938701010882882129983692583827244388026884467058917978843169668001171451334636280790077811565946929966688641164998966066111013287422907348314383296894102327707300862411876615010916578656534937113384325633993177654883178110100920159716830597702547365724945713850139732813071768558547327363869114244097858925321821295844619627401599616808091078007379762443913212295772300688564526319150192417027988288243200193273385961134775125193371477919837758878397560197949439736581
flag6 = 10956113850377048530496385896303978246518495602476059839708140065275776622781166280399435874484992350703541709836363294485217041027405484561887557581985267787193202481664525888885620545301558817938942792910107790676789747845277671018691586617649638492081483915243205577522327116280378480334628503026394734763944985692939266582718918931540254885455662165547702813570286669998198151627316488943145246831407469349681033737914393634573010730411028914727083873512187560371918250728988188439410108765014419745291644289981506131313180874077229025611478092977735833628182537447281054545450143948781400107915705806191253423218

n = [n1, n2, n3, n4, n5, n6]
flag = [flag1, flag2, flag3, flag4, flag5, flag6]

hastad_unpadded(flag, n, 1337)