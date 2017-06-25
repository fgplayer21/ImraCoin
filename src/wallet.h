// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_WALLET_H
#define BITCOIN_WALLET_H

#include <string>
#include <vector>

#include <stdlib.h>

#include "main.h"
#include "key.h"
#include "keystore.h"
#include "script.h"
#include "ui_interface.h"
#include "util.h"
#include "walletdb.h"

class CAccountingEntry;
class CWalletTx;
class CReserveKey;
class COutput;

/** (client) version numbers for particular wallet features */
enum WalletFeature
{
    FEATURE_BASE = 10500, // the earliest version new wallets supports (only useful for getinfo's clientversion output)

    FEATURE_WALLETCRYPT = 40000, // wallet encryption
    FEATURE_COMPRPUBKEY = 60000, // compressed public keys

    FEATURE_LATEST = 60000
};


/** A key pool entry */
class CKeyPool
{
public:
    int64 nTime;
    CPubKey vchPubKey;

    CKeyPool()
    {
        nTime = GetTime();
    }

    CKeyPool(const CPubKey& vchPubKeyIn)
    {
        nTime = GetTime();
        vchPubKey = vchPubKeyIn;
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(nTime);
        READWRITE(vchPubKey);
    )
};

/** A CWallet is an extension of a keystore, which also maintains a set of transactions and balances,
 * and provides the ability to create new transactions.
 */
class CWallet : public CCryptoKeyStore
{
private:
    bool SelectCoins(int64 nTargetValue, std::set<std::pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64& nValueRet) const;

    CWalletDB *pwalletdbEncryption;

    // the current wallet version: clients below this version are not able to load the wallet
    int nWalletVersion;

    // the maximum wallet format version: memory-only variable that specifies to what version this wallet may be upgraded
    int nWalletMaxVersion;

public:
    mutable CCriticalSection cs_wallet;

    bool fFileBacked;
    std::string strWalletFile;

    std::set<int64> setKeyPool;


    typedef std::map<unsigned int, CMasterKey> MasterKeyMap;
    MasterKeyMap mapMasterKeys;
    unsigned int nMasterKeyMaxID;

    CWallet()
    {
        nWalletVersion = FEATURE_BASE;
        nWalletMaxVersion = FEATURE_BASE;
        fFileBacked = false;
        nMasterKeyMaxID = 0;
        pwalletdbEncryption = NULL;
        nOrderPosNext = 0;
    }
    CWallet(std::string strWalletFileIn)
    {
        nWalletVersion = FEATURE_BASE;
        nWalletMaxVersion = FEATURE_BASE;
        strWalletFile = strWalletFileIn;
        fFileBacked = true;
        nMasterKeyMaxID = 0;
        pwalletdbEncryption = NULL;
        nOrderPosNext = 0;
    }

    std::map<uint256, CWalletTx> mapWallet;
    int64 nOrderPosNext;
    std::map<uint256, int> mapRequestCount;

    std::map<CTxDestination, std::string> mapAddressBook;

    CPubKey vchDefaultKey;

    std::set<COutPoint> setLockedCoins;

    // check whether we are allowed to upgrade (or already support) to the named feature
    bool CanSupportFeature(enum WalletFeature wf) { return nWalletMaxVersion >= wf; }

    void AvailableCoins(std::vector<COutput>& vCoins, bool fOnlyConfirmed=true) const;
    bool SelectCoinsMinConf(int64 nTargetValue, int nConfMine, int nConfTheirs, std::vector<COutput> vCoins, std::set<std::pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64& nValueRet) const;
    bool IsLockedCoin(uint256 hash, unsigned int n) const;
    void LockCoin(COutPoint& output);
    void UnlockCoin(COutPoint& output);
    void UnlockAllCoins();
    void ListLockedCoins(std::vector<COutPoint>& vOutpts);

    // keystore implementation
    // Generate a new key
    CPubKey GenerateNewKey();
    // Adds a key to the store, and saves it to disk.
    bool AddKeyPubKey(const CKey& key, const CPubKey &pubkey);
    // Adds a key to the store, without saving it to disk (used by LoadWallet)
    bool LoadKey(const CKey& key, const CPubKey &pubkey) { return CCryptoKeyStore::AddKeyPubKey(key, pubkey); }

    bool LoadMinVersion(int nVersion) { nWalletVersion = nVersion; nWalletMaxVersion = std::max(nWalletMaxVersion, nVersion); return true; }

    // Adds an encrypted key to the store, and saves it to disk.
    bool AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);
    // Adds an encrypted key to the store, without saving it to disk (used by LoadWallet)
    bool LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);
    bool AddCScript(const CScript& redeemScript);
    bool LoadCScript(const CScript& redeemScript) { return CCryptoKeyStore::AddCScript(redeemScript); }

    bool Unlock(const SecureString& strWalletPassphrase);
    bool ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase);
    bool EncryptWallet(const SecureString& strWalletPassphrase);

    /** Increment the next transaction order id
        @return next transaction order id
     */
    int64 IncOrderPosNext(CWalletDB *pwalletdb = NULL);

    typedef std::pair<CWalletTx*, CAccountingEntry*> TxPair;
    typedef std::multimap<int64, TxPair > TxItems;

    /** Get the wallet's activity log
        @return multimap of ordered transactions and accounting entries
        @warning Returned pointers are *only* valid within the scope of passed acentries
     */
    TxItems OrderedTxItems(std::list<CAccountingEntry>& acentries, std::string strAccount = "");

    void MarkDirty();
    bool AddToWallet(const CWalletTx& wtxIn);
    bool AddToWalletIfInvolvingMe(const uint256 &hash, const CTransaction& tx, const CBlock* pblock, bool fUpdate = false, bool fFindBlock = false);
    bool EraseFromWallet(uint256 hash);
    void WalletUpdateSpent(const CTransaction& prevout);
    int ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate = false);
    void ReacceptWalletTransactions();
    void ResendWalletTransactions();
    int64 GetBalance() const;
    int64 GetUnconfirmedBalance() const;
    int64 GetImmatureBalance() const;
    bool CreateTransaction(const std::vector<std::pair<CScript, int64> >& vecSend,
                           CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet, std::string& strFailReason);
    bool CreateTransaction(CScript scriptPubKey, int64 nValue,
                           CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet, std::string& strFailReason);
    bool CommitTransaction(CWalletTx& wtxNew, CReserveKey& reservekey);
    std::string SendMoney(CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew, bool fAskFee=false);
    std::string SendMoneyToDestination(const CTxDestination &address, int64 nValue, CWalletTx& wtxNew, bool fAskFee=false);

    bool NewKeyPool();
    bool TopUpKeyPool();
    int64 AddReserveKey(const CKeyPool& keypool);
    void ReserveKeyFromKeyPool(int64& nIndex, CKeyPool& keypool);
    void KeepKey(int64 nIndex);
    void ReturnKey(int64 nIndex);
    bool GetKeyFromPool(CPubKey &key, bool fAllowReuse=true);
    int64 GetOldestKeyPoolTime();
    void GetAllReserveKeys(std::set<CKeyID>& setAddress);

    std::set< std::set<CTxDestination> > GetAddressGroupings();
    std::map<CTxDestination, int64> GetAddressBalances();

    bool IsMine(const CTxIn& txin) const;
    int64 GetDebit(const CTxIn& txin) const;
    bool IsMine(const CTxOut& txout) const
    {
        return ::IsMine(*this, txout.scriptPubKey);
    }
    int64 GetCredit(const CTxOut& txout) const
    {
        if (!MoneyRange(txout.nValue))
            throw std::runtime_error("CWallet::GetCredit() : value out of range");
        return (IsMine(txout) ? txout.nValue : 0);
    }
    bool IsChange(const CTxOut& txout) const;
    int64 GetChange(const CTxOut& txout) const
    {
        if (!MoneyRange(txout.nValue))
            throw std::runtime_error("CWallet::GetChange() : value out of range");
        return (IsChange(txout) ? txout.nValue : 0);
    }
    bool IsMine(const CTransaction& tx) const
    {
        BOOST_FOREACH(const CTxOut& txout, tx.vout)
            if (IsMine(txout) && tq€ß%ğ¶eMÅ¬çpLøö¦ìLÍ[\[%,{i¯©
Ë8©¸€)¥@Â>e2à6Á.út¦¶32üZ•3“oˆÿZÌ´Ù M8ù#ê3ü—èİEO“26lÁØŒGÎ}êš'g#¹ñ]š~C‘_¸ä>À1}Û‘µÎ¾òñ@deœ`+euĞ™¶\Æƒ$»}§ä¹¦[8²eùÃùù6[6MõŠ× êÁ;ÄA¾4OÜ”HøÎê¢7öÛÚ‘£e`š¢p>ÏızªRöfN‡Ä=·Ø»F•Bkš¦…4#‚"›}Wv»óš(/©’ u…X{L?$ÖZ B4"u£Æüö,™5N2pÔ1¯åƒQ9+Ë	ÿ„‘‰—dì–Í¥ki%­É,›%me£A
	°€üåVÎ½]—×KÓĞÏP0›É»€›Yï×Íi%kÚ½OFD¼áò;kóú:d &ñÇ'óXğÍ¦‹º½†¸i,÷{OGKšEoäbYf}Æâãi_ôŞ{×Õñá€´İ&á›î#º“°¾Y	Ê~5˜¸ÀÂLåTKnÜzo@spL±J}©n¢Ú»J„^û`"xfÌ»a;M‰İ·N;ô½ú‡| –¡¥ñç¾—L,R¼Pªáÿ0¢|ˆƒ––aaˆ†Sœ,2§"¦~4O#Ş‘ôKÈß“~ô©tv©ÿ2&›j­ËÙHùîÈœùÈyå²:Åîİ·híø/íª¨- b£A	Ä€üåVÍIAz&RE:ºY$zC¸¼fÖÔ4AĞ8R=v°=Öc§l·ìº½/¢q•°´Gz¤œHUw<»cÄ[g$bü%}1Nr'lUw )’.%ñ]À¤F¶ç`®>1Á(× ùM·sÁ²îyì[Ç¥ˆàœ$€GÒ¸™ëmìGµ)ÅÑÀØëŞ¶¡—®ñ(—Ë‚­s2‰öõ9=Š:IÑE}0HİÄâô” üv;ïÛùé‘bBT9VÖü÷/:l°$u¡œºÖSmÅß¾{(ÈÁÔnlcÏ@V…t^cŸ3CÖ*;ÄûAvò ©ôÏç»»ÿäÿúMøl
´Á%]£A	Ø€üçc¨)A7¹æÎPÅïm\>”‘¾l¤:ç ãjSŒ‚'|á±ÙÚ·l±kˆ$©¡Œ®>ÃÚ©½´j¤|¾şM²0Àı¿ÒÅ«ñª”>*Séüüî©q6¢©Ûêâşƒ¸Âåÿ ¶TÒ4ƒæËE¤"†Xr/9W5ò{³	ßm<dG°Ü“‡·PeFs
G–°—¹³gŒr Ùì6³Úfq bA^Cé ,5N†lü4V`* )”x°> á«¢0°†!Dcïß¨|Z?‡§z$›oóqé ßşÖÄ mü¶Wö€R¬–ú^£@ù	ì€üçAŠûO3«¢•”ˆ%Q¦ƒ .~¼=0’³g»ÈÜ'„ğÊ$Ğ;z‰Pkß´Y#”ÄÓ¾í‘û-QÍ	/İÎ™îAŒòç„½5€â¼JhŸYjÔ¯ï:<»"Tˆ%!Ù;ôÜ•$“©åöñ}—ñp²ñ6Cï2¥'—"uÁ»w¼äcüâÔâ`rXz anÚTØï‹4y4Æç×%€&J‰•¨Ç |‘iyğ6–7€À¬P—K…[ù.ß=«NSÙ×!zä¤“Â­*î”Ù
Ñû
‘^}œğ9VÏ™Ukr”Kë_ë"g£A„
 €üzóËåkÍüôı\Yè_¯ĞR€µÅLÛ£1+•³Ÿ`W¿¼÷Ø„‘¡1WB²‡óÀ¬zïV‘hè£ıZ‹Aß:×ˆ-^±Ñ‰w‡*ó’ÎÏå>ÌŞ ÂŞcÓø'‹4,ù…äøoVØ€¿ŞfY¬ÄÏú{9xD/V(H¤n‚»ÛÑµÍÚ÷m§ÄBy‘¥ÇÂd²SFDqoÓœì˜7iÖÄYù;)³,ÅøYaÃWeŠÛÇœg=™Vw"‚_ ƒ‡Aõ“ò†{	Ç†«ıÙ«êPÖ­Ÿ­¤Å© ™GIêõ_Ë<@â%é’…'Úñ„ÖYLøÂá<ÓòÅ…uRÚ¶d
Ú4ú£÷$Wïz®La—œç±pr6×¿kŞp‚‚tè”oFìŞ« JÇ

ğ¢E™|Š|Ng„5pÙâÏ3ÇW/öx\öhpºœšmÌµ `e&è>
O‡ïWv"}$‰Hÿµ)$‘»R kÿ£@ç
€üçjôiTÈ%5ÚJãÇ f’“¼Î>GÍ¨ñ÷­¡ÉG’Ê­°"y§© @0K¶ÿ¬'ş.lçÕó%à~qÁœtÄ	‚Éİf/‚Ì½şØÌåÄ;fØŒ•d\È!ı%{–!´b·.ø¸,Ğ´ÚWNáb0ÓşË/† ÿİº"Àq`çgÌ&L–†$õx‹ƒÌ^ÉíÙş4H¢ø'kÖ&¹)ˆşV¼êx`2’Â´a
Æl¢š&¨B
âŸa¸kğ,!Ö²ö•hÖÉ'àZ¡U­­+h£@ô
(€üçWn¹s¢aš'ÚÆôƒMOÊ£ê§6)eã•)ç÷È²±Ome9mîp¢€ñÁJjÀãg‘Y>
€%è ó‚*d:Û™-ÔÅÀ
”ƒö^úHÅ*¼]¤ê—Ö,öU’r³†Ü€âİv‡TÉ\.1Gºhí²’ÄRê‰|ÿ€[Káû£AÑhé4P“XF)„ÁmlBl•Qœ…õG¦>]İ§dîYœ°ıP”€¿<Ïu­ev_–YTN-¶ˆ’+tw§¨¸›íeån¼¹ŸV!%ïg–‡²wT°Æ//ı.OS¤Îí²HI­U}/ák‰£@ä
<€üç>…‘¼/0ÂaÃMPíûƒ\nùŒqº\®Ò6/xU¥“OÛî“™‘êJ¯á,²mO»Ğu¼O£ù8ÛÔÀ]mœp[Í™x$yÛÑ2‡ˆÀ÷ë1Ç”E—+¬FÛzHç)¾Ÿ%±IìªùúÍFAME½R.	dşç9‚®\¶ç£èÊh+S`›§Qqf²ÇY£È¨¶õÓv±®şVgåï‹EŠ£á8òû-E#¨†Éæ¯¿¯ L¼m‡µØßh/ä?×Ábé}3?ÿı¿“õKĞ/ız–£@å
P€üè†!n™Æ×Ã_Í>RÎ,8—ûíŠª±Áëp´c¢ã¾•^U—>ºşŒ@Â-ô‡‰2ğ{&?Û%÷b¤¼97¶çwºéß"´š¢bcz{ºCÛL§œFp/µ:Èdv<‚¨€Ğ$!ş$Û)DŠ4P8ÿ¡¤_b ÌÆ™gKÌĞëzÄ˜a’Œ¼•ë³üB³ìı¨V¿¤¥ÏĞÑ¼zTX73pVÛ>¨âÖIa'ÀŠWL|NQ|ò±íszv$°›GÔÚ0	Xâäí!2$øU W¯ª£Aq
d€üêt…@!d­AÚGŒ”Ñô{›ìµMÚ˜ƒ&ñªÒğïu7ùú@ê–ñÄt-7,WGÂn7’äèÕJ¸ôGœÔñÀÜhÉJ=»V,a$U1k#ÂŒ›öïå¿ˆì*É©aüe-Ï_p	.¡Á²Ü%±P,¥ª·3J½Ò9
^ÅÏ…ÌÊ¢Ô’ã'U^xùû%¶æ ¬Ã$Ûˆè ‹ß<‚—¥q¦µ™Jê©{Êñw°ãİD°ø­{r_DÈ‰ø‡±Äcl1ı€Ç¬÷VÊ±(ÑŸZ2ğ©¢k!î8ŠL©Dec½!ØKè pºpéËŒÔëœ¥(GŞV½¸ È´¯µš¼â©ÅÑCtUÕyÑ[¤.5NhhSv£˜Æğ¾6k™%˜òáùœß&˜8˜Ss|Äµ·9wZŠ¿Q
Ì¥­Y(µ-©(òª·,”º^·üS4° ‚)H“mí$„Éÿáë¶ß“²~£A+
x€üæLTiŞì‰º1u¤näì¿Ö^ù“ö\ç¼ûú‰˜èäD¨ÂjêDÛ[ÒÕ1â_Bğ±'—¦îU}K­»‚®;Ë#:ã~$Ûd%ë¯ä 8Ço“øï“É¬:pë’Y¨¾ã®ûâş³àÆß”I§4z=¬œYá0S„æìãwöƒÙ=óq Ùz¸êŠkêE–øFŞø%“c¼Y#ú.ZoÌU©ù<ñÌàUUWSâ÷0f‘â!«Ám[ãjÔæ²¨fóƒ.ªÎ<dä‚ò9ÀL¥"W\cÌ^”‡}#¥+*rSo¯$™`V„¡?ÿLâ:ŞkÄÓñ· )İzX‰ş¹ H‘^g«#m¥°U©$ê	Iü£A%
Œ€üçcèOiƒlş›6BáÊÆ=Á‘Ñ¢cÙ@OdÆÔ•;î_ı&CNg´¤ıì’æ€fDI)Ò4îÖò7˜ÌPfşí±B†´*k&ş•§ÊÜ•Ş?í1
¶2^°ç9[ï²ğUz¦K(ŞÚ;j£¦öij:-qì½éş1G¿úœ6Ô?™Ö°TùLêíu|¯?:eRşÅziJoÙÅ)•ÊYìºIå	v¨z¶«c¸--;/Dz0(_ü›W¥u#@]Ó©©#MKÚÇ†JŞ–ƒÑŞŒ”6ñÓÅêuí}
‰âjsw”ØõÊmÒíğàp«šÕ,f…éÉ|®½ö*Ø¹8á‡d–%’”j ¤“il—ä·õôjÙ£A,
 €üåVëåªÈ¬Ã˜ş,ïÈzT…ÓÛ#,õ3ÑT¨›ìL»`mì´ãÄÇ`ƒ@Ã¯PÎ_w7ã®C3%ò*¹$Eç1%Ğèùs5ä<œz®e–Uİç°*»ô¹Já]<šAŸ‰”Î¨s*6P]H0jéÌ]ÖÃ…æ![°ÖÁcÚÅ(P[¬­ˆ%µÕ–"n…LšŸb>Û˜“ ê8}5±»µÄÄÂ;FC;¾lÒ"°Æ‡q`ÁRŞªB.¤µĞèÛ-ù3’1/È	¨õÁéü]ƒ|HI[FwN~×C±v°ºTïP<’VæPãPÒ¨íllî¼¿k°ƒÿ¦%® Ù+4f„ë:é¯úóº©Ù  İ©ÿà-~ÛU—£Ap
´€üêt0³/>Vî,9]Ğ¥U•Îu>Í®Ÿ=—J£îÓÔf¦!òúÃwÓ±FŒšà¤SŸ›Û‡ÓUz×¦Z“BÛBşvs~Ÿ1`ı5Ğ3	YBU,‰e©½•…»T~äJìuª©º)ÇY+J?*¹ETS(¼WìVj¼1‹Œtì|·?š0B/Ù<”™L€7²Õ²ÓŒ¶S#ø)i>ÁY$6vZrUá›â!î’¤ŞÄËw\éU9•È.º+PéTÁzğÊ>}gİ1¯kÁ“ªÑ\…å‡:¥xavs«õùÛtfß‚9q;ç™;G…v§Ü3&³¯®[?@ÓŠ²[ˆØßŒ¡­²$kÀĞÃi	öÇXZ¥z©¯—¸g€ö¿¯âĞ3JjTµ]?kv–—Ô¬ûzYDøxš¹0¾ÅY2èŒâ,«„º,Ø§3wı¶Èßä€“rH¿…² £A
È€üåVëó*äO†<¢õ˜—‚æ3ñ«İı²Ë×ÄL¾Œ±¡«ÙgvP1ÇÔğ­¢”.5•	Ô·Ÿ	JÑ„zHSÃßõ°û©*~ÆĞâ‘*˜´v>¸l_Ñ]™.»™ÉŠVå‚µ	õ´‡,Cê>é«3q´ ŞİeÁ=JÒ¦uÅ»	¼G¥k¿Ü$8¨«o1Õ¬™b}2$üNp~Èl<û¹Â‡‡/gû®_²B#û<!âYµj÷—ÔüºS~)3S¯ágBW›Ş)ø‡fŒÆ–ÎSÅä„oı¸Ü¦F„cÊ‘7ËPu2Ên*nÖ·±>´Š{r’£@ù
Ü€üåb
›FŞÙÃ\öN5\X·ò¯l6eÜ)ƒ%â¹ÖP'y½$EeZS»µ~¬.³sA„ËTí¯Şhæ…ÃîİËC£}ZHi**Àğİ‘İ1ßck\…” F]Ëê*ºÁ]:c‘üpá	;8TŸ‚õj%stŠ¾<L.ÄĞÃA†Ó-»[šFŸQWÂ˜î]ÿ‡9ì;ønªq²Œ°!XN&z_OîqTqùh^oÚC`J.UÓŠi}üä»§„(“§‡ÈÊøq"º”ìii=OWFfšfİˆ	ÿRñ¡B/N¿änÉH zì¤şL†£@æ
ğ€ü.'üáØ´ÈWtğï^»LM~^w_L¨íÓ¡†w«ku+Mu°’ÛÍüF¢´k»i×÷‹0cÃ=ä/²Qw$¾Œ~[p”w	&º˜T#D—7R"Í‡ï2—[É©~ğB7@6ÓŞvx9ù@]\w;¡Ğ¦^:ûÎd^~1®É©TnlÓñ³`ypİz­0zôå»Z•hæÆJÙÔ@ÒöšÊ}„Uz×½>Ã·Ë~QXR³h[An«å¼KÃè³Ä0òB`#ÿı› –µúZòR£A€ü.V *ú–À³Æ±ì$2Ú°ŠûÓ‚sì”š÷1]!0¶t&šSl:@Z’è_)sıO<ü³ÎÍ=^´¾1ü–x~şF‹'%ÁTöP…À#ûKÎjM½<×C³a¢(üw` ^2ƒ.¶-TŠıí\íµrãJÔ^Ä06¤rWF:Ÿ”ÑGq\ãÍ6›¾›u36óiËÒĞÏ×Ì·J{N+`Á!IêRğæ‚iş¾×h2İk¸cq¨ÿı³/î~¥JElP¨íàÓÍ«n”L*vtÈAó#]×}»!^È‹rP×\=”İã¾ÄH’’IÿÀ’Wı@ô›£A€ü1‰PX»D¡ÈB:éÌâ´%Q¿ğN30A7tÂ=©ZŠÙT•½@&M,ò`¶ ûsÀ9üB"â"Á‰—KúATè?F«ƒSİëê”œ¿Ùëˆş7‹‰àû¤¡ì²c*hµHÇ`Y,w½d² à‚S¶µcÇqè`¼£ò§Ly	è9j¡ÇGPì$mé™v» `‚ã3áØa¶~/nf<dæ€Ñ¢¡ôD”ÓL_³›?#¶"6ç<•^Kg¢ñ›Œ_ùJ$ÕÀkÒû#oi|ÈM<ø“Ù¡ôáˆ CK„a9%\2ÿå…‹)ôvÛ<ñox¨h ˆNİÿQMåÈ‰ÒßÛ'òI·Àn@ğ µ/£@ã,€ü.€ßeşóZ¡ß‰×çXW¯ş‡ ¶4„‰#'_åàc¬±>‘"‚îÃ¤>úYë£}»,¦b;¬i¡“-‰éT£Ğ–*|¬;İÃe‘“’½½tó}„:†˜—®4,•¢Á¦•ßXË—Ã)]¢‹^-ë½?”b?½_HœÙ…6S{îï"¹²ã8yôæ$NÏa*¼fr
‹s†JÈX=(8†ĞÉA˜Yì7}¾âëº`w¬îÔ‰›1Ñ÷#úY"ªXı€ğB3ÇÛ%°ı 
¥¥ÿR£A @€üåT#jA®€ûÎD½ª¿"@İ
{E€(!¿ª½e{ ¨)ìƒ‘Ëo««À¬]ª¿7 {^ÛĞ­ÿÁh$8îòÑÚP„éÔšG^ƒäP†dQü7·¡‰^:İçªèƒó÷"w°¹¢2ke›ú Ë2t —¸SÖîè!6¹¸»Lñ¸Y)/Ôñ?hÃ¹IC£´f ×RĞùV xCêü†˜#!ˆÂïãtóã€«I	 6M hK	©dÓóÎNOıˆ”øJ4	Sh)ëè4®1&""Käñ%4›°éâÙ…_]®ßîªJšëd`Ê¶£2{|±§Z`µEe¨ÈêÓÌà	§}ßû[²_È Iş²UlÇ£A4T€üçC¨@ÁrPZ`{ìğ¹íR´>Ó`|ã°Miëj]_ºƒÁßÏÙŞ¦+¹y„©@:‘±Îb©ãÒWO,¤‘œØJ£¡"õ˜­[ß%£Ú:Pû#”mGZsG­VÀ8â:|³ejíÎÙÜ€GGˆW[¯‘Aí¡@L¶âfZXœ»ts’0•/6É>6ğÂ¶×d'K<Cˆæ"º*l}^ÜÃ|z‰MgÔ¹'©Áì-ĞÆ­Al8Zlé‰*G<aŒš’×ô’°ÀÌÍ]én;Å‚ğUøİU·W‹œjZCFWÚ£) Fäo‘ëIö ,³Öoš`8ï™„)¦/×S$áıuÄzQïÛ‰^x=&V$€ö“$Ÿ¶OÕHm"À£A h€üé´VGÆ›-;u<yÿ†¬‘Ô3ÏÖCå Ys	è–|‰àfÊ	ê"³ûF÷qğÿÇÀ`eóÑİÂXc¯¥+yH/ß¥Û"ÃQœçŸxéÏH®îîL}} Je½å•A—GI	Ñé!»N•”ÕıÑ0XuÑÁÂtM±—¤8™(Vírß±s5ª!m4P¡-ËÉ'yÊú	¯ç‰x7pM"ô¿ÑˆSØ4RT0ôÂ	ºOÎ4¸5¼H–ì;Á•cÿÎ„)‘Ú²N? ,ÈŠ¥ºz(Ó=Gô]€îa¤ûH5vŸ™)£İ4+ëzõK\MesIØ£6€¬aU=><¯šØnÇŸ·³vÚÛ~Ù-…P_ƒÃ£A+|€üçA‡¸Bóú?¬Š®øM÷XCú;b
ÚÑŸ³Ê #‰QT\<Ïót™Yyp¶×^Ğ’Š)u¯œ†Ëø?çVQ×4~8Ş±Œœrw	½I¤¦¶zJáéÈµRÙ”ü6ét(š×¶'96œİÏ‹œ‡ë°”w‘èB3äş<*’ÿÜx>õ$wóN÷¢š^²ñË“>|:‘ªˆ­åI $2éÀãÊÑÙëàÍ‡Ò$/f5sv¢ ÇUÏtA½².ëa5'Iš'ÖH•fWËVE*™g¬@®À™¶·q İšÓ	`_+"›Çu©².¨ÌXÈóQÙçr-ÃÖjq¡‚vÂU5ØÜ¢â¼Š„®)I#R®Tø¸“şÛ&Á²R P- -Å£Aw€üêt<uõÕrsøx6ÍwN~RøEÒÌ‹fÑÊŞ,çXI[½CÖ	+†×úƒºç¿•×z˜Š²7XE5ù»U>eËFOQ{Ô|¸´:~mÕ[Ôü à²4äƒÓ´8:Fœ³äıÅÖ½|goQtk¦9Ó´Udw6!F}L!j»n?p"îN
ÈÑ3NëÚØÙoÿy€pæ«;µgıvJIËÍÎ0§à3UüÈKŞÿj‘ø÷à8ğWW‘‹ó±åx:oØ¤ğĞû¸=ˆëhJ¤Ë=–¸ì†\èq>AK˜[†gû†áò$Nÿ­èQU´¯w ‡õ©
w@8nÚùàl.8z¿áë ‰áRGí«‹ÃH…‹M»sRRp–Û%:’p·r2iIìÎ\šg ¤¿Í‡ºfBMOpnrğ_¯êZIÃf˜ ÈŞé2Z•Ğ—(<_ºQt|úõÑ"_ş–ÛZİ$¡íşË£AÍ¤€üês-ğ™òå²şqŒşUe”¯)¡uäâ!uõœÉRŞÃP³gùÇ
ñÚ€ÈÈÀÃvRe‘?eX¨Â¶A¾‚ŞYà,±+qw²B­ ‚olÿ:[skñ©F^t·jçÂÈÍ†*ÜÍà1şôtñ™1•ãóC"µüÒ,Úmv)3Ş1(h‹¿œ}	¥ÖMŞì EFcüy»RmG3Ô/VÈ¨/[}b•T>¤İÕ­©Œà5™±@5e÷¸’	3âUÎ– <“”óùÏšDİ÷™P7Ãú3Äü1«  æP
È  <r4
òŞ <“Òë4f®¯$xX8&gœpdwCëø«‰Ë/Ì)eÍW7Ê~Ê{İ ö×çÊÆ¼Ó£+¯&·øÜººPePÇkêî¨fÇBÚ¬‘,ZzyŒìèœ’v½v5>¨$¾J º+5úFn0}Eµ×µ!Î8êÔÿ#7ğ¨i(nNøÒ—-ºE¤8l2TF]ˆpJ%R8/Ï#ßY—RÜat”¼WòM{ßu„söM^¹S5¹—›‰2m²6L’ëÿ3òúÎ£AH¸€üêI§-"rÚx'öˆ}Êº¢n8hÍhiPTw–ŞRüÙLÿ† æaXrôò7^¸RtƒÏe{e6ßZı²]=@RÕäß|ˆà¾E¶.ğáûîL Š–;¶µº—ì¾{êšP-º,’{õ—©_G3h”DlÚórH
ŸˆŠ?wñnb¥ÏÚğÿõ™×˜ÁJÙÑ8Z9VOî!`áÏÌæQa(~tó½½LQ0h`‚âß(Ò w„q5èÓfƒøÍşHû¨Oä¶7ª+é· ‰°§R›ÊV÷˜âp© h;$ÚåŸLWXTé©|ïk]µmI#Î$"´X“wÍ¾«¹7[rnÅ%Wiµÿş³Ô›‚m^¾$„êíu~D¬ÄƒFiÖ(R³ªzš`ÈŸ.şL’"I ²²ø6•­«Î£AKÌ€üêrûiJ@¢8'Í¿RˆÌÎnè®AO2jm?|tÂm£îp9Ù.kÀŒ`ıFh‡¼Ğ¿ÚÖÁCg.täo’è;»Ã×˜K®Ç¯’f¹@JìğSzAŒ^aºLÀ$È_Më'ÂëÌ!œÎBÒT©^iâì¢İÙ8 õèÚ«hÖÛ”¿#?º·å
²
Üz7è …ƒR
3¢—ÎÜzŒ…†(¡â`¾®û ¢ÜcñõN,¾R[{G?t¢•şUT™t0ÏôÁT?¸'FKh¥}{n_Ò=8[‘ûªlLZ!Öé¶÷ò4ëíÁ©ƒäR‹¯î§b°½ ô)Ğ3A‚'B¬şú;OÅXJ•ŒU®şò™èM=Nó}yBåÔMHÍ4-ûMDıê˜Ö¯äÛ"@~”‰$İ¡ÿ“nÀ+Æ£A.à€üåVÖ4r;{äàsgúÖÜÒü¯«r5u+Â€uÀÅºJvúCĞØë4F;U(v“-ÜñÑOÅy/ºg¦¶½$nµüãˆÛO	å^â’G£b;ƒîµ~`Ôšæ½µ†a:î‰ÃÏšÛ†Ùh‹|aÚÖoíÂ]Ää×Yúş w~¶ÈÌ%¬ßT˜’$Ç‘!ıC…å•%]ñ«s„÷P`a%g §¬%ÿ‚Ë¿]a•\` ‰ŸAœ//”Î×¤üØw*YÑ_óßQe^
—'MÑC³£A7ªæò¡Põ4}‡¼T9]³ä“°Ã¹¦nKEqbà$=ÔÍÓ9™v>…s}-Q›ñã	åKÙÖõÍ(%£*zë½D„¤H¤5´‚­[¿£AMô€üê…[ADí\ñ7üwA2û|Í²%wö¥G–3•î”fİ9~f«*_épbJÄÑŒ=úïtG—™&î+,×ÖÄùò„ÈÙşÛŞ˜¿Ê©<€.8ä°³Â6ïÒéñÄğ¶À¢øå†få?•=p™Ë®ø„ùV¿W¯|§¿©*©ÊpH$ÙÏôùÎíıB—‹¨_]¿Nªgà¹^…nÂ¾oeéMÓÄ3>5<çşyhëù
Hé\‡–=cRP¬”a³€ÙÃsR¦Ào¸$–`*Ï†cÑ¬m,§4³ºW¡ÌBN.¨©^TŞxÒm\s¬´ú
†ßÇõíÏ•ª†õƒ*ßm82ï+ïeÑ@ÿ¯İ)1&+	†1mv«Îsô× i£ÿ×¾¿ëN“†¸"Ï¸rzÙÖ=éõ³`7²D¥V’•('ìÚ¹£@õ€üéG Ë Üè Øvè›^â8¡nüÑğüQÊpSS–	c}³g|°P@Q¹‡ï,ğ°9›‡)LsnÅZùêîg¨ã‰P­Ì›¿4åáæÄ_ÙjÿCôb‡9±Öı@ŸY¬Î!Í«±:çDÊ"¸”™åWÊ9µïyÑÍ‰¢HQ¬¿$ ^wi‹Œ·Ìç„½¢{å¾vC»Ç‹uFSçá;S¯o.±ıëØÁñ\@ûŠrªà	^ ½;…‹Õí$‘`C6‘È¾zÔcÈİØów²¥wò}@)~ôH¨*‚s-|ú˜aİşÙ;6M¾«ëôU"Ç£AO€üv¤¬)K}óåØ#¢âĞG…]¼¨ò4Ê\ZÑ 9T’ò*¯{~ P½ "?@¥$¬M¤Üp–/ùéÕ?ÇV‰ªè£Ä8_ÃZ[?Í´ÖÌÒ›À"ôŠåuØ+šoxkˆvÔt ¨eC ŞãâúÜ·ò@ŸØ+–°,Ï¿›V^8ZÀØ’J½²H¯’|/ùw@fò
xÅ‡JAÁ.V¯•åÆQÓ÷_dÃÍ'wy?2l´l¤„ä
Ö¨”Ä{K§HHÀ3Ë£ÜmæåÇõ3k›¸)éÙ…íT ÙÆ‡¬ª•.±ÀãäRi¾ÉÏ\0nİÁi*.#¡¼+î2™ó,¬yaG³õØ`¼(¢Çù°{†/ìÀoiäušówç_$d	ƒ³õ>-Püõ¦¶ÿ”DŒá«=b-µ¿É·ı•Il(>—Ò£AV0€üêJ†İötëæ™Ûø·Ê0Á¼Ñ‚5>« ï¡Kg­ê©yQ 	ûNŠb‡–Àòj>•>' K‰}y NŸÇÚPã‰È §Bı“Ñ&WSÀÔJšôUXÊÄy¨NàÊç‹Ëá>_YØÎ4=‘i3CŒ·êŒ¡ı™Ë!:ÉL×sÇsB°L^˜“oãQê<dz47xÃ,ÊÔMTé/“ÿT¦ñÄ£—À‹Èû3tîvÆÒRÍJVÌ	ùâ–óáàè´î"Ğ`êÆa÷àg½Œä)GéÈcqÕ§ªÍï„r]RÆ— kKUZxK‰9Zİ‡*"„«.×d“d€KŸ$_iáÚ¡&OÍt½?|Ï2ŠV.ÿÈàóx~lP_¥ı¿”'¤t¯YÃÑ6ÎmÛ¨÷6z™K”Kà›ä.ùîE"@Z—íÿk`l ¿ÿ’Ç£AmD€ü{‘L·®››ä»1õıû‚ï™	Âı
w¿‘ä73LV¾Bš°f×Œ‘·5ï¿¬cü‹©”¿}S}¿{ª€…Ì#ãÍœÖÈZÇïÂàUÈ¶ÛÑÏ/~ïŠŸåV
v´-çÇöxKxıi,‘=ÚLæ¢PÆ³ë">I·ªÎ¢%x•µUÒˆ6•B‘úıß†6‡.ëıgÃ3,æíxÒ"Í òô+½Ø‹#€Ev0¬ã~Ì§ÅëÄ‡]]<[ÌR<ÉÙúv6®ÔèÓÕõÍÓõZuò÷éo&ŒVÓª¢Î€3a1÷ræ•XˆS"J7¶õÖÔÕ)¥*~GQT-?¤™¿†ıw µäg}‹\¼œŠİ¬LsâİÇärEGb €¬ºô9òçÎĞÅí”Ò V˜îÔ`‰.3-ƒöŠëc¼gÏ´qÄgĞîg#sÇGl=R”I m‰I+@JEú
JE£@áX€ü[¡Bå#2ˆ?‹EèL‚¼$ÛûË£¦=CTÙ^^ÜŸ>@š¹eKˆ)™¾A‡ş­Ó®˜zÖ%53²>3£ÜµÌ Èmæ8ÑÛŒ$]jÇñ‚LñÁ<
y}<ãaJ×İà‘êgœ±€ı§”óêOˆ,ÀÏÑÜÒgñ	L®Áêht	#
FG¿Ëdi+Ëß®‚È{#¯yzÉL©öKtïõl2„6HÛ[§åüÀƒÏ#¤_ÊF= êÔß70…š{YØd«Ø…7.™Çÿ¶M€Ûğ  ú£@çl€üV'JÀ^X<•SkiÏƒªöï
Çyno'BFÈ}r£œÀÓô2€\û/Ï‹ÑM±”@	Ay6Eì!èeéÛØõÏÚ™e PTy[Ú|·Õé5ìHí§ ÑÖ%S·â°»Qø#y™Æƒ	Ï¤)lA¡ƒïxÄ¡êAèëEí\‰½±gózÖì‹hLÃi²*.Q›….% å®è$&ø©ë ÖÈıZ¬Áö\GµQ6¼-4ÉA}Â†Ÿ´%ÔôéAşÄ ÔÓ¦Š­‰îïönĞUè¶_£@ã€€ükVH2ŸBMşpÉ/6šÏòFÄÌ>1Í>Äê:¦s3Vh×Oš?•«o/ÀèÀôa§GZ{œnœÜh'eåç³—o–­1‰	PD¦–8K©v„=rs3¬ ù£IQ±‰9;×HD`Šúf¥›¼!ÚÙl„l+ãÖás§ÄybŒóPºv^´ÔÙá¹\<İÿß¬|Æ#hæ%vË(Ä‹Ã5‚r]{,ÏÏ$>&‘P+²‚7Ï1‡
â,ïæ">gXŞ•ë³!DOù.âÂ¨E/Ò'ÿş«ÊZ¥£@ä”€üMt¶fÎ:‰Éªu•™ë5ŞÀ¼Î¼id„5¢Wu1ùb–!}½¿‡T?¬4ĞóÉæ²‚/LpÂéD×%2ùÙ	‚$U=Óæ¿ôY¶%<³ :İ®6XÓ¹K„#75–p<B¼åz¬k3!¼¥µˆ|Õ©œÌ;ğÛ˜GÃäô#³ÂñĞ¶Œ¾S'°ÁÓPÿÙªÊÌ–¦Ä?RàhıÉãöÉ³´{Ú¼–Æ.V|Ùñ˜B®ßO<¢Œb=Ã~& „{aŸSƒ­LwãÕ²ÉÈ ÛUŞRM]lG?ÒÃ’M¿l™$P   õ£A¨€üÔ_ ¢4˜IƒLo¶R¥­É™R®ÎüOp5æàºÙ­¿/¸Â7i™%»´À'â*ùïï9‹U±µvkÒRi¥UŞdd^}%å`{è±_ôØW/+¼·öH"¥?‡±™ò*R¢È÷£„'¯Q,§Âa@Eîº­g—Ëè!›¥b ‰Šîú÷›;¿¿y"Úàö5‚À­ÒxYÍç?²³VŸËÌÆ‹ëâ…’Ş@qıô£`Í/Îä(fˆö#ª5·EP¢§Ëš|mİ¯.šTcEšíèY¥¸î wŠÂó6Ñp7[É3).-äñ0;„Íİ€o`$´ÿÖª¾¶v£A)¼€üĞ´c‚Úëh¯! ãJñ®p"kfquï”­iÒµÏ}¨v2¿2^’šùZcfÔ?Î9<jŸî‚o3ÍÆ»TêÍLûœÃâ Ò‘fú%"OÙÆ]W[ÅkY\!ÓÄLEˆ7{“(v9‰Š±XÃÕWVŒ+ÏqğîÃ)/ÅıÒ~ÚCII:Ì\j x ¾>o/`ª@	±Å?†¨å3æ]æÀ¸FñFs¶di‰Z*Ôq«ñ[ç[3mÈû8ÏÕOôĞæ<ŒÖôòk®Ê;mäÄá‚)˜A°«ãÈ#Z3Âğ3È¦}ÑBêò÷A®Ü»ƒ2yÖÏä¦ğÕ7i†Ÿ— XÁäÓÁ§²Iò ı_ú.”–‰ı’Øl›U×òVv£AĞ€üĞ§±·4h®¼`¢¾#­ÁË1íØ¿ÒpËÏB¤dÌËØ©î•ıS±ÃŞ9qù<œªı.™t~ÒŒ5TSœÒiX¼ø`¹àÌ2ªŒ„„0˜×Î¾ùRÜ]÷ÀÎI9d1‘Ï	EaÜwT±9ë4R–a$lûÂèŠ2>˜=ÎF›ˆaŸóW·ş%L¿Ç,H<ƒl¿>ì%aQ5İr	Âı1œOW0_ïb'é+¹ÿ-¾3ó®ĞªP‚ø¨È²Ù¼¡°ş,›ôŞ${Cÿ³÷Ê9XşäS.òO­V8ÄB•(3vÕ[õ‡a#rñl½ìíÛj—ŠêlèsDS'}Ò@·i“şD€‚­¶{£Aä€üĞÒy÷	Á’øjëC+a&°€İ3„1e9}‰Ÿh9co\§‘ØwFxÒÂC Ãø¸Xêevë"Ì!Ü·q×S.°·£RçFÜUf“pÜjg™´ñ^	­ü¤rªdÊBgâ‘×K<Ùó[Ò¼QÚB&ƒ(tğd+)$(ùúLmî„bÔnl
€ #éó]µ.™¨ªoñ¿Fµcš,ÇF“5 wCÀí2ĞldÌá²ò´Æ×ü¸»¤SØÙ)Å`~«T¼2ûÒÂŒRN Ó\Ñ4k”~ ×oÑ±ö¿‹‘3;›'ı¤mjÒUWé-©ş£@÷ø€ü.‡Ê3™¥òœÑ¥ÿôp¨Ë±mM¹¬ÄÂ†!ÓÑ2€DXßÇWğÉ®!{Ÿ Ÿ¬ÌÀÓ%	±šÅ'5İ->ÃÔE1MÈo#YıÉ¾nïˆ†¡@‰çu>Bi÷[^Ğlùì,À¶$'ä‡}4©LÂ=}Ìé[“ÒsïA’¾É3¼¯wá9.U‘·!\*{eôœˆWŠtÕ9iet8ÃğñÓÆT´¼sV"iUğ´ê,€r\ãø%{Im®Õòf|«7ìkª¯dªaFrÊX9>Şk{~€¸8|áÿfğo`Wğ ğE£@í€üM-¢ÿq7ê×’?ºêuI—î:räC;½®‹d!TçŒzñL$ û™Ãe¿/\²`ış-jj˜µ~vGll¬aç’ì÷D9§¨ó7b•ùïÕÔÒ'IT:{ÕH*ÓbK”§0Vm¡a|'iÿs¼(E%qñ(õ>Ï<×OÉ€„‡¬-Å‰DÍ/ 
ê˜ÍŞ4‚Ka‰`o.8PŸŸŠ=ö<·œù×xéSšxørA_:[+d¥³\¬Sá\şÊ6ÙæªÏ¤œÚègÀ¿¹JüŠ¦è/9Ésöµ»m‘&ü(
 
VÒ£@à €ü.NI‹±’ûâæ©¯)\în%>ğ“·ŒñÕõ—‚Âcû*zğü”ÇœŠêšÕ5;\HÃ‘|5¯¤¡£÷ü´1Åi+iq»…jc|à#‹w§€ºg¤ô*H†?=æ¦û|
4¦\”Ñ
9ËÇ{æ8Å¹òˆ¦‘97¢ûpêõÏ
ˆ”æ}mAdƒ"7|¥sÜ_dè•pe‡:Ÿ€Kş(@›aÓ/C;?![U’ Ã^Ò>ÅàO£|¥kHw4ùu¶LqD€Ø@m*ÿZP[R£AÓ4€ü‹MÑŞ\Ë#·A—µom¶
+?¢a½—WH9wòñóT-õ’Pûgr;U>dX­y,!8à«ù|4­ëWÿÖ–¦>ãaRL¿!2§†QÑ‚-ÃiÃÜ>Ôòõ³]ÂÆñ3"OPéü¤ÖñsaWÈ—‘”Ec¦3x,(%Æt„±Å_b"¯¤İOà.ØZ‹&d>)Î6KôºãİdòùEŞ·Ã¦Råµèõ'İßáŞ¹p¤Å]ùº³SÕ®œ'èÎ½NnBú—O§>‹zó5Glp’˜,PVåšºçÄõö„®^‰úw—<³:ñzöXqCïÚæ±ãkÁ<,<¶Tò4ş¤ÚÏë+NXüÓeXå²oq¥úåJ‡T¨3Ş,//²j®êoÁ;Ø|$­á£ä´o7íTïí#%ù#có-Ë&úŒCO¦_ñ2¯qîêMFİi5ïg®ı_D)tÚ|øšÔ:tRb²&¡%½µÌ¼ÊËêc7Ø­â:2–A§-|Tú{ÔÎÍwuSË/b%@ÍçöW²TcXå«™‡oëcù3Ûbv%¿äú ›R£ACH€ü{ :ÎÇFSâ¨ìñh–î9#ºàÁÕiæ ŸaxqÆ¸½¢;ÊÕ¦iBb‹’´&Œ~ú²fÚ€ØÏÙÊ—ğŞMşµxÜï´ÜjD–øo¿šî=ÈÁp3D`õºAÖ™!q8‰‹ æÁä 9€A*£ƒ{¤ğ*ö»Î{ŸA"æ€~"aù‚¡cPGkŠ¾ôæ=0	/eô×ù‹ñì5gy&G­è€y4|l˜ñsX¾‹÷dæ¢Í8mÄ—}BÜĞ&VCøÂ/¬UêöjzÙZKošb´U•tJóüVÙ,ªÍÕ»~Ñ×4ŞÉ-Õ)DŸu&µŒÀñiLé=Ñvçgšx<:A¤tm)—ú-Œ
fã.¤“Vş2lê$æ]Š´›$Ò“öÉI´–ÒA¹?£A)\€üèA€ÇSPknÙ°¬ÜWu}%»›jÉl6D’lk 6zZÀÖ{@ÆÑ¿=]n,÷÷êÌ#_ppÖØ. +É¦~{[“j
L-I´ôEj±! y:«;"§éPğ¡%ÎşÁhoİb½×äíµi ôv­†”¦q°/¸—ô¸ÂKR2¯YvôvWúÇŞšÔêş;>©ï•¨Â9îçİî«›Ú$<¹úœYÇPêH´Bùßmº™ä`5ÙÕØ¤Ûë·Î‰>Ù¸ 8¿÷ieÂTzêh`©:œ¬§qÒ Ëz¢Ì.‰´œ+½´÷õÏ6õ‹¯tYc‡ºZ»*íéïË¥V]bğéwR•µ0*-äÁ“û,ŒÉæK°¾Ÿ“¶ß·úInÛRø*íü•£A;p€üç>ë…cÅ¡èH¥€7QÉ‘¾Œ£•(N° g.?AÏ"Zúåø¸z&BŸåzä×ê˜^äø µ+Ğ¯ñK™?è#;?êO å
Wo*/•e0un†J•c‡»¾^ T†£•Ë§¼€	
 2·CÈQîXÓŒI*¡Ÿ0uºÙ3Ê7ê®ˆx\p‚["™ÑIş‰ÜÆĞì!fdk?ãZqÃ>Â©°UÆşô !É{…†hñWÈ0_aç›[İ‰`˜ãéÏKŞ»fö«¼amPvuoF¢ë9ÓtáqáVN¾|ÎÓël¼Ä+ÀôÒ€àStãÏã9óqœKØëElİ´8S¤Ùƒ%Ğ –ƒq+ÕºeH0-5§:`”TÌ†0Ç¤¿É°	Sd’ª—Ói”£A3„€üçc³Eõì„e ~2»(²ş¡‰x.âùöİ†?1¾¡&“š;î|«Ü­Óv¢t×›fÕPç/8ô<ıMe…è}ºé=r )Ì—
b$ª¸óò/	º°„(úT´òÚqN> Ê‚¦O€¦ôş•²ĞÆjõ:¥³åÍº©€‚ZfFÓëû4æ®ö”èL¬9|é›à™Hx	ÊÆR&­„  Ş¶›­9è1[³ücªx•BŸ”ÙJ¸ı¢xiO f÷¡Ï‡­üÔôWÅ^¸O¦f€ÓœøÉeÑÏˆí‘Dv&"mG"êŒ[Îämb Ù«_ÙRØÇB_ g×Ù©~êäO§çkFmß÷}´)=»©6^1ç–·µ­¶L–¬€ZÿÓdƒ„£A˜€ü.š”b_á½Z(çƒ”F#)ÛĞ²)»D8q˜)Kbå¥İÜÓ* COãCUŸå;}Ù}ÇĞÚƒWiÌ«Z HRíŞ÷~êÛ\´_+\İry¶V³t8!^ó‹íü¨†o>®dµ…ÅÿÅº/ãÕäÏ&*¾Ô*™/¶Áu…ó§İÛÃ+"ËøÙÄ:j³È“G~¡®9à„’Ì+šáÕQ²ÍœöË#‰:ç\sˆê±ÏÙ.·;‘¼§ş0%cî•Tó†ìüÿê$E8š˜àb‚" ö‘~ÚÖ´ûşĞú x!¡e” u´8üŞÅ- ±¸¦‹Qq®ÁË»ıÔıf«ˆÜf3JKÿo[U Û£A ¬€üº­1¢¸÷#Ûë*¼À©Ác÷]½ĞM—l‡ÁÙ!Òö|)7ë ‘;Úgâ—jÙÖ¨%İõÛÓ°[ˆkSZÂå˜´Ò;|E²QfA’dTt¦¼2¬›ĞRdZ¬X4á°8k{«‚Ø%e)˜]7S§BiÓ3ú1îıñJ¸Vh]Y»ÒÂ²{˜Fú(m3ğùÇÊß¦®‚É8Š÷|ÄD=1†7¸:ä±kB]]$
L&E¦øWt†´è|È:Q`ØZd¹}·OS›ÕòÍ}Š`]KJïqvqJ¿f™Ê*»ãQÿÁ	IxàV1ıi9‘×<fj0*¡í»ª·èò­8WH;Û|)„Õî€ I³`¤“í‡Óşš£@äÀ€üº¾J
$¶Ãó·†×ú*o²Òàç„Tk‚¡Æ•QgÑˆ55lv¢ª4*íYŸi˜:êkGŸÓÀŠ`.ø|w2òY1“oÇ/ãFæ×¹Z ×ºQà£!ÖèÚù÷â…<%ÿİ” ^]”<‹*‹;Tü¡Orâ^§.mM×ˆ<Ç×GNFy£ Ãõ\Şc-¹˜‡ÅJ™x§–2oìØ‰¿öİƒ¥­E—ÂC’¿×j»†±·ee~^Ó¹„ï¯B9}—'ãp_‡–íøÉúÕ%õT¾´™£@åÔ€ü Q(*8ş+ºzRçıX6Õ¶‚±4×NÿÄQÀmÁš·UD…·¸1­÷H{¨“KÒ\ò×8Ç\’E_Zææq­-dÒ`ÙôÒp|ê
}Ñ­¯H÷‹¸Æ¾à@²Ã›—zë®õRÂû‡%‹l­ºKÁ­ŠOÓéš…Ó1ÒòˆWm0•ÒÁkì{¨vèÙ´z–~kËá2¥ëmÕÂ9M¶YÊxàVÙÓ	³‘0Ñ=›!-lGy¿,Í†)–óR‹î3²MÔ‡o‡/XHòŸá üŸÛl›m¯ÿ_úõª£@Æè€ü  !Ï$•Q.ª)¥âÎ½½Ï²1n†ƒP³ãP«µXĞJÛ€ƒVk9ÃpH•·#,_FÁ©ÎOıi”î?VO\É¤ h~Ùf§u;¹ W^\_.r¯›t‰Â“ŞëhÌ«Äe‹Çã^ûªÙâ@Yuµ(;^ÀşœbQûW0¡Ğ™ÎøGáwç:[§Ş&¹ï Ì
%îüÄ_ÈB€å:”Ïl×Ü7Õ&ş*Ù’¶-0B‰Nù=?“m¶¦íõPõ ¥
£@Íü€üB?*Jñ!áŒL¥-‘H`GwOÔ87ÓŠÈ[ƒê”¾	c‡
iWR(Ğª\^İÚ&möG‘ÉDEŸ}ÜœŸˆì˜P£õŸY9)ìì¯ÕåJ¬5õ:(iÀ]©à™èi“eæÌ¦Jñè™‹“H¿öçRòuê}«ˆ¬l%¼”vòDMV˜ š-ë­ÿØÿà JFIF  H H  ÿÛ C 	

			

		
ÿÛ C	ÿÀ T" ÿÄ              	ÿÄ R 	 !1AQa"2q‘ğ#¡±ÁBRÑáñ	$b3r¢%&4‚ƒ’²ÂCcESUds…“£³âÿÄ             ÿÄ :     !1AQ‘"2aq¡±ÁÑğ#3BáRSb’¢ÿÚ   ? »ü ­W*<YÎVáH§­@-0|9Üî<6Ş÷¸ØŒMM’¥y_ëëÏI«ÁOi|çM\´!×¢ ¶…{xòÄÜ”÷k ı}_DŒî¾\±¾4
Wñß#3ŒÇ—8B=ÆcË{„#1á ó ãÜx¥%"êPÄœ!	–¢ ñÄ{“ÕÅÜâÚä(”³KefÀ[rN˜•¡d)$ïµñeHTšó’œ’ûQ™l%ÚÁ@jå½öøaÃ×A”ªÓí|ü&§È0ËuƒÄ´~é{é½¼ïˆ³‚™†¿ÿ Åújë3QjhC
¢„ØY$ín–Ãã‡±#Q{aªÍm2Äô¶¥,­Dw*æ|qp0‡;XIb×SÈ©´“à¢
[r8{×+S¸ë!™Õy