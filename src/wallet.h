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
            if (IsMine(txout) && tq��%�eMŬ�pL����L�[\[%�,{i��
�8����)�@�>e2��6�.�t��32�Z�3�o���Z��� M8�#�3����EO�26l�،G�}�'g#��]�~C�_��>�1}ۑ�����@de�`+euЙ�\ƃ$�}��䍹��[8�e����6[6M��נ��;�A�4OܔH���7���ڑ�e`��p>��z�R�fN��=�ػ�F�B
�	����V��]��K���P0�ɻ���Y���i%kڽOFD����;k���:d &��'�X�ͦ�����i,�{OGK�Eo�bYf}���i_��{������&��#����Y	�~5����L�TKn�zo@spL�J}�n�ڻJ�^�`�"xf̻a;M�ݷN;����| ����羗L,R�P���0�|����aa��S�,2�"�~4O�#�ޑ�K�ߓ~��tv��2&�j���H��Ȝ��y�:��ݷh��/���-�b�A�	Ā��V�IAz&RE:�Y$zC��f��4A�8R=v�=�c��l�캽/�q���Gz��HUw<�c�[g$b�%}1Nr'lUw�)�.%�]��F��`�>1�(� �M�s���y�[ǥ���$�GҸ��m�G�)�����޶����(�ˍ���s2���9=�:I�E}0�H����� �v;����bBT9V���/:l�$u����Sm���{(���nlc��@V�t^c�3C�*;��Av� ���绻����M�l
��%]�A�	؀��c�)A7���P��m\>���l�:� �jS��'|��ڷl�k�$����>�ک��j��|��M�0�����ū�>*S����q6����������� 
G�����g�r ��6��fq bA^C�,5N�l��4V`* �)��x�> ���0��!Dc�ߨ|Z?��z$�o�q� ��֍� m���W��R���^�@��	���A��O3�����%Q�� .~�=0��g��܎'���$�;z�PkߴY#��Ӿ��-Q�	/�Ι�A�����5��J�h�Yjԯ�:<�"T�%!��;�ܕ$�����}��p���6C�2��'�"u��w��c����`rXz an�T��4y�4���%�&J���� |��iy�6�7���P�K��[�.�=�NS�א!z�䤓­*��
��
�^�}��9VϙUkr��K�_�"g�A��
 ��z���k�����\Y�_��R���Lۣ1+���`W���؄��1WB�����z�V�h裍�Z�A�:׈-^�э�w�*����>�� ��c��'�4,����oV؀��fY����{9xD/V(H�n���ѵ���m��By����d�SF�DqoӜ�7i��Y�;)�,��Ya�We��ǜg=�Vw"�_ ��A���{	ǆ��٫�P֭���ũ ��GI��_�<@�%�钅'���YL���<��Ņu
�4���$W�z�La���pr6׿k�p��t�oF��ޫ�J�

�E�|�|Ng��5p���3��W�/�x\�hp���m̵ `e&�>
O���Wv"}$�H��)$��R�k��@�
���j�iT�%5�J�� f����>Gͨ������G�ʏ��"�y�� @0K���'�.l���%�~�q��t�	���f/��̽�����;f،�d\�!�%{�!�b�.��,Ў��WN�b0���/� ���"�q`�g�&L��$�x���^����4H��'k�&�)��V��x`2��´a
�l��&�B
�a��k�,!ֲ���h���'�Z�U��+h�@�
(���Wn�s��a�'���MOʣ�6�)e��)��Ȳ�Ome9m�p����Jj��g�Y>
�%��*d:ۙ-���
���^�H�*�]���,�U�r��܀��v�T�\.1G�h����R�|��[K���A�h�4P�XF)��mlBl�Q���G�>]ݐ�d�Y���P���<�u�ev_�YTN-����+tw�����e�n���V!%�g���wT��//�.OS����HI�U}/�k��@�
<���>���/0�a�MP���\n��q�\��6�/xU��O���J��,�mO��u�O��8���]m�p[͙x$y��2�����1��E�+�F�zH�)��%�I���́FAME�R.	d��9��\�����h+S`��Qqf��Y�Ȩ����v���Vg��E����8���-E#���毿��L�m�����h/�?��b�}3?�����K�/�z��@�
P���!n����_�>R�,8��튪����p�c���^U�>���@�-�
d���t�@!�d�A�G����{��Mژ�&����u�7���@���t-7,WG�n7����J�
^�υ�ʢ���'U^x��%�栬�$ۈ� ��<���q���J�{���w���D���{r_Dȉ����cl1��Ǭ�Vʱ(��Z2�k!�8�L�Dec�!�K� p�p�������(G�V���ȴ�������CtU�y�[�.5Nh
���Y(�-�(��,��^��S4� �)H�m�$�����ߓ�~�A+�
x���LTi����1u�n���^���\�������D��j�D�[��1�_B�'���U}K��
����c�Oi�l��6B���=�
�2^��9�[��Uz�K(��;j���ij:-q���1G���6�?�ְT�L��u�|�?:eR��ziJo��)��Y�I�	v�z��c�--;/Dz0(_��W�u#@]�
��jsw�����m����p���,f��Ɏ|���*ع8�d�%��j�
����V��ȬØ�,��zT���#�,�3�T���L�`m����`�@ïP�_w7�C3%�*�$E�1%���s5�<�z�e�U���*���J��]<�A���Ψs*6P]H0j��]�Å�![���c��(P[���%�Ֆ"n�L���b>ۘ� �8}5���ĐĐ�;
����t0�/>�V�,9]ХU��u>ͮ�=�J����f�!���wӱF���S��ۇ�UzצZ�B۝B�vs~�1`�5�3	YB��U,��e�����T�~�J�u���)�Y+�J
Ȁ��V��*�O�<������3���
܀��b
�F���\�N5\X��l6e�)�%��P'y�$EeZS��~�.�sA��T���h�����C�}ZHi**��ݑ�1��ck\�� F]��*��]:c��p��	;8T���j%st��<L.���A��-��[�F�QW���]��9�;�n�q���!XN&z_O�qTq�h^o�C`J.U��i}�仧�(������q"���ii=OWFf�f��	�R�B/N��n�H z���L��@�
���.'��ش�Wt��^�LM~^w_L��ӡ�w�ku+Mu�����F��k��i���0c�=�/�Qw�$��~[p�w	&��T#D�7R"͇�2�[ɩ�~�B7@6Ӟ�vx9�@]\w;�Ц^:��d^~1�ɩ�Tnl����`yp�z�0z��Z�h��J��@�����}�Uz��>���~QXR�h[An��K�莳�0�B`#��� �����Z�R�A
�s�J�X=(8����A�Y�7}���`w�����1��#�Y�"�X���B3��%�� 
���R�A �@���T#jA����D���"@�
{E�(!���e{ �)샑�o����]��7 {^�Э��h$8����P��ԚG^��P�d
�џ�� #�QT\<��t�Yyp��^В�)�u�����?�VQ�4~8����rw	�I����z�J��ȝ�Rٔ�6�t(��׶'9
��3N����o�y�p��;�g�vJI���0��3U��K��j����8�WW����x:o������=��hJ��=���\�q>A�K�[�g����$N���QU��w ���
w@8nڎ��l.8�z��� ��RG����H��M�sRRp��%:�p�r2iI��\�g ���͇�fBMOpnr�_��ZI�f�����2Z�З(<_�Qt|���"_���Z�$���ˣÁ����s-����q��Ue��)�u���!u���R��P�g��
�ڀ����vRe�?eX�¶A���Y�,�+qw�B� �ol�:[sk�F^t�j���͆*���1��t�1���C"����,�mv)3��1(�h�
�  <r4
�� <���4
���?w��nb����������J��8Z9VO��!`����Qa(~t�LQ0h`���(� w�q5
�
ܐz7� ��R
3����z���
�'M�C��A7���P�4}��T9]�䓰ù�nKEqb�$=����9�v>�s}-Q���	�K����(�%�*z�D��H
H�\��=cRP��a����sR���o�$�`*φc��m,�4��W��BN.��^T�x�m\s���
������������*�m82�+�e�@���)1&+	�1mv��s�נi��׾��N���"ϸrz��=���`7�D�V��('�ڹ�@�����G � ���v��^�8�n����Q�pSS�	c}�g|�P@Q���,�9��)Lsn�Z���g�㍉P�̛�4����_�j�C�b�9�֝�@�Y��!ͫ�:�D�"����W�9����y����HQ��$ ^wi����焽�{�vC�ǋuFS��;S�o.������\@��r��	^ �;�����$�`C6�Ⱦz�c����w���w�}@)~�H�*��s-|��a���;6M����U"ǣAO���v��)K}���#���G�]���4�\Z� 9T��*�{~�P� "?@�$�M��p�/���?�V���č8_�Z[?ʹ��қ�"��u�+�oxk��v�t �eC ����ܷ�@��+��,Ͽ�V^8Z�ؒJ��H��|/�w@f�
x��JA�.V�����Q��_d��'wy?2l�l���
֨��{K�HH�3ˣ�m����3k��)�م�T��Ƈ���.����Ri���\0n��i*.#��+�2��,�yaG���`�(����{�/��oi�u��w�_$d	���>-�P������D����=b-��ɷ��Il(>�ңAV�0���J���t������0��т5>���Kg���yQ�	�N�b����j>�>' K�}y N���P�����B���&WS��J��UX��y�N�����>_Y��4=��i3�C��ꌡ���!:�L��s�sB�L^��o�Q�<dz47xÐ,��MT�/��T��ģ�����3t�v��R�JV�	�������"�`��a��g���)G��cqէ���r�]RƗ kKUZxK�9Z݇*"���.�d��d�K�$_i���&O��t�?|�2�V.��Ȏ��x~lP_����'�t�Y��6Ύmۨ�6z�K��K���.��E"@Z���k`l ���ǣAm�D��{�L������1�����	��
w���73LV�B��f׌��5￬c�����}S}�{����#�͜��Z����Uȶ���/~�V
v�-����xKx�i,�=�L�PƳ�">I��΢%x��U҈6�B���߆6�
JE�@�X��[�B�#2��?�E�L��$��ˣ�=CT�^^ܟ>@��eK�)��A���Ӯ�z�%53�>3�܏�� �m�8�ی$]j��L��<
y}<�aJ�����g��������O�,�����g�	L���ht	#
FG��di+�߮��{#�yz�L��Kt��l�2�6H�[������#�_�F= ���70��{Y�d�؅7.����M����  ��@�l��V'J�^�X<�Skiσ���
�yno'�BF�}r������2�\�/ϝ��M��@	Ay6E�!�e�����ڙe PTy[�|���5�H�� ��%S�����Q�#y�ƃ	Ϥ)lA����xġ�A��E�\����g�z��hL�i�*.Q���.%���$&������Z���\G�Q6�-4�A}��%���A����Ӧ������n�U��_�@����kVH2�BM�p�/6���F��>1�>��:�s3Vh�O�?��o/����a�GZ{�n���h'e�糗o��1�	PD��8K�v�=rs3����IQ��9;�HD`��f����!��l�l+��֎�s��yb��P�v�^����\<���߬|�#h�%v�(ċ�5�r]{,��$>&�P+��7��1�
�,��">gXޕ��!DO�.�¨E/�'����Z��@����Mt�f�:�ɪu���5���μid�5�Wu1�b�!}���T?�4���沂
��#��]�.���o�F�c�,�F�5 wC���2�ld����������S��)�`~�T�2�����RN� �\�4k�~ �oѱ����3;�'��mj�UW�-���@�����.��3����ѥ��p�˱mM���!��2�DX��W�ɮ!{� �����%	���'5�->��E1M�o#Y�ɾn���@��u>Bi�[^�l��,��$'�}4�L�=}��[��s�A���3��w�9.U��!\*{�e���W�t�9iet8�����T��sV"iU��,�
���4�Ka�`o.8P���=�<����x�S�x�rA_:[+d��\�S�\��6��Ϥ���g���J����/9�s���m�&�(
 
Vң@��
4�\��
9��{�8Ź�����97���p����
���}�mAd�"7|�s�_d�pe�:��K�(@�a�/C;?![U� �^�>��O�|�kH�w4�u�LqD��@m*�ZP[R�AӁ
+?�a��WH9w����T-���P�gr;U>dX�y,!8����|4��W�֖�>�aRL�!2��Qт-�i��>����]�Ɲ�3"OP�����saWȗ��Ec�3x,(%�t���_b"���O�.�Z�&d>)�6K����d��E޷æR���'���޹p�
f�.��V�2l�$�]���$ғ��I���A�?�A)�
L-I��Ej�! y:�;"��P��%���ho�b�����i �v����q�/�����KR2��Yv�vW�������;>��9����$<���Y�P�H�B��m���`5������Ή>ٸ�8��ie�Tz��h`�:���q� �z��.����+�����6���tYc��Z�*���˥V]b��wR��0*-����,���K�����߷�In�R�*����A;�
Wo*/�e0un�J�c���^�T���˧��	
 2�C�Q�XӌI*��0u��3�7ꮈx\p�["��I������!f�dk?�Zq�>©�U��� !�{��h�W�0_a�[݉`����K�޻f���amPvuoF��9�t�q�VN�|���l��+��Ҟ��St���9�q�K��Elݴ8S�ك%� ��q+պeH0-5��:`�T��0����ɰ	Sd����i��A3�
b�$����/	����(�T���qN> ʂ��O��������j�:���ͺ���ZfF���4����L�9|���Hx	��R&��� ޶��9�1[��c�x�B���J���
L&E��Wt���|�:Q`�Zd�}�OS����}�`]KJ�qvqJ�f��*��Q��	Ix�V1�i9��<�fj0*�������8WH;�|)����I�`�������@�
$�����*o����T�k��ƕQgш55lv��
}ѭ�H���ƾ�@�Û��z���R���%�l���K���O�隅�1��Wm0���k�{�v�ٴz�~k��2
%���_ȝB��:��l��7�&�*ْ�-0B�N�=?�m����P� �
�@́
iWR(Ъ\^��&m�G��DE�}ܐ����P���Y9)����J�5�:(i�]����i�e�̦J�虋�H���R�u�}����l%��v�DMV���-����� JFIF  H H  �� C 	

			

		
�� C	�� T" ��              	�� R 	 !1AQa"2q���#���BR���	$b3r�%&4�����CcESUds�������             �� :     !1AQ�"2aq������#3B�RSb����   ? �� �W*<Y΍V�H��@-0�|9��<6���،MM��y_����I��Oi|�M\�!ע ��{x��ܔ�k �}_D����\��4
W��
����Y$�n��ㇱ#Q{a���m2����,�Dw*�|qp0�;XIb�Sȩ���
[r8{�+S��!��y