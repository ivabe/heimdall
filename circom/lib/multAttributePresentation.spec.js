const {
    prepareTestFolder,
    prepareTestCircomFile,
    compileCircuit,
    getSnarkjsInfo,
    writeInputJsonFile,
    exec,
    readOutputJsonFile,
    logger,
    getConfig,
} = require("./util/helper");
const chai = require('chai');
expect = chai.expect;

const config = getConfig('multipleAttributePresentation');
console.debug('config >>', JSON.stringify(config, null, 2));

const attributePresentation = async (inputJsonFile, testCaseMarker) => {
    const {
        pathToTestFolder,
        testFileName,
        generateWitnessFile,
        wasmFile,
        wtnsFile,
        zkeyFinalFile,
        proofFile
    } = config;

    const pathToInputJsonFile = `${pathToTestFolder}/${testCaseMarker + testFileName}.input.json`;
    const pathToOutputJsonFile = `${pathToTestFolder}/${testCaseMarker + testFileName}.output.json`;
    console.debug('pathToInputJsonFile >> ', pathToInputJsonFile);
    console.debug('pathToOutputJsonFile >> ', pathToOutputJsonFile);

    await writeInputJsonFile(pathToInputJsonFile, inputJsonFile);

    await exec(`node ${generateWitnessFile} ${wasmFile} ${pathToInputJsonFile} ${wtnsFile}`).then(logger);
    await exec(`snarkjs groth16 prove ${zkeyFinalFile} ${wtnsFile} ${proofFile} ${pathToOutputJsonFile}`).then(logger);

    return await readOutputJsonFile(pathToOutputJsonFile);
};

describe('multipleAttributePresentation.circom template', async function () {
    const {
        pathToTestFolder,
        pathToCircomFile,
        zkeyFinalFile,
        pathToCircomTestFile,
        r1csFile,
        powerOfTauFile,
        zkeyInitialFile,
        fileName,
        verificationKeyFile
    } = config;

    before(async function () {
        await prepareTestFolder(pathToTestFolder);

        //const appendixCircuit = `\ncomponent main = AttributePresentation(4,13,4);`; //The line is already there
        const appendixCircuit = '';
        await prepareTestCircomFile(pathToCircomFile, pathToCircomTestFile, appendixCircuit);

        await compileCircuit(pathToCircomTestFile, pathToTestFolder);
        await getSnarkjsInfo(r1csFile);

        await exec(`snarkjs zkey new ${r1csFile} ${powerOfTauFile} ${zkeyInitialFile}`).then(logger);
        await exec(`snarkjs zkey contribute ${zkeyInitialFile} ${zkeyFinalFile} --name="${fileName}" -e="random"`).then(logger);
        await exec(`snarkjs zkey export verificationkey ${zkeyFinalFile} ${verificationKeyFile}`).then(logger);
    });

    describe('AttributePresentation(4,13,2)', () => {
        it('Success test', async function () {
            const inputJsonFile = {
                    pathMeta: [ 0, 0, 0, 0 ],
                    lemmaMeta: [
                      8649556902979350474375734489292062430308873812564353739302985524914933190503n.toString(),
                      6936141895847827773039820306011898011976769516186037164536571405943971461449n.toString(),
                      10977980966834643138728730053226485292633849451273876782504771219740619389015n.toString(),
                      5619023039337103829616697496339402563534172352509019011936112645847852693139n.toString(),
                      677379545312290885192364459534376921307283949759062033809263067517956009893n.toString(),
                      12074323598234007102732157354247427466996348051342899105857091560891721396879n.toString()
                    ],
                    meta: [
                      '1234502',
                      6936141895847827773039820306011898011976769516186037164536571405943971461449n.toString(),
                      '13655875959156446041003686450727543277577607343640957596198614440905192406953',
                      '418345881136734657821536929192100652128513241165040801294274854880593629315',
                      9037940188198198671970800601490910088551427182609940173326074139244911486789n.toString(),
                      '1728651690772',
                      '0',
                      19014214495641488759237505126948346942972912379615652741039992445865937985820n.toString()
                    ],
                    expiration: 1699102553831,
                    signatureMeta: [
                      '18153206323213243732758181250625825132393935736800161909754855504316636117612',
                      '16189365432687316114751909163348615227739232519391635784382076051790486927093',
                      '2578215604840987506520722462618763733996712910109724601230219814843346725554'
                    ],
                    issuerPK: [
                      '4643259722160863894017222732038903736516965842816039081564323609562274366098',
                      '16525374212653837622881411417931955478254733897688458811072534400359914775645'
                    ],
                    pathRevocation: [
                      0, 1, 0, 0, 0, 1,
                      0, 0, 1, 1, 0, 0,
                      1
                    ],
                    lemmaRevocation: [
                      '19014214495641488759237505126948346942972912379615652741039992445865937985820',
                      '19014214495641488759237505126948346942972912379615652741039992445865937985820',
                      '10447686833432518214645507207530993719569269870494442919228205482093666444588',
                      '2186774891605521484511138647132707263205739024356090574223746683689524510919',
                      '6624528458765032300068640025753348171674863396263322163275160878496476761795',
                      '17621094343163687115133447910975434564869602694443155644084608475290066932181',
                      '21545791430054675679721663567345713395464273214026699272957697111075114407152',
                      '792508374812064496349952600148548816899123600522533230070209098983274365937',
                      '19099089739310512670052334354801295180468996808740953306205199022348496584760',
                      '1343295825314773980905176364810862207662071643483131058898955641727916222615',
                      '16899046943457659513232595988635409932880678645111808262227296196974010078534',
                      '4978389689432283653287395535267662892150042177938506928108984372770188067714',
                      '9761894086225021818188968785206790816885919715075386907160173350566467311501',
                      '13558719211472510351154804954267502807430687253403060703311957777648054137517',
                      '15093063772197360439942670764347374738539884999170539844715519374005555450641'
                    ],
                    revocationLeaf: '0',
                    challenge: '1234',
                    signChallenge: [
                      12243097771010616781290173970357380624543480859300372151596642622338342068677n.toString(),
                      7158243247130698738365721829221899672161681700413447673359275795322723226276n.toString(),
                      2046753221435243869622188326951147017772334889085503967106516336790136313561n.toString()
                    ],
                    lemma: [
                      [
                        506091454650568783913867607798865803589405944288788850564754505122530534451n.toString(),
                        3682517034118067363988451114871104117228742174037622396838237067437565515056n.toString(),
                        18878883468345056588699621447839481715498959820038966040077003347610463634329n.toString(),
                        618638519746699582528549692212284110327326234632368094768493192902850827193n.toString(),
                        2918767623888005859665423957392086466868735058622622032600698859626808312691n.toString(),
                        12074323598234007102732157354247427466996348051342899105857091560891721396879n.toString()
                      ],
                      [
                        3682517034118067363988451114871104117228742174037622396838237067437565515056n.toString(),
                        506091454650568783913867607798865803589405944288788850564754505122530534451n.toString(),
                        18878883468345056588699621447839481715498959820038966040077003347610463634329n.toString(),
                        618638519746699582528549692212284110327326234632368094768493192902850827193n.toString(),
                        2918767623888005859665423957392086466868735058622622032600698859626808312691n.toString(),
                        12074323598234007102732157354247427466996348051342899105857091560891721396879n.toString()
                      ]
                    ],
                    path: [ [ 0, 0, 0, 1 ], [ 1, 0, 0, 1 ] ]
                };

            const outputJsonFile = await attributePresentation(inputJsonFile, "successful-");

            const expectedOutputJsonFile = [
                '6936141895847827773039820306011898011976769516186037164536571405943971461449',
                '15093063772197360439942670764347374738539884999170539844715519374005555450641',
                '9037940188198198671970800601490910088551427182609940173326074139244911486789',
                '0',
                '16480984838845883908278887403998730505458370097797273028422755199897309800407',
                '0',
                '1234',
                '1699102553831',
                '506091454650568783913867607798865803589405944288788850564754505122530534451',
                '3682517034118067363988451114871104117228742174037622396838237067437565515056'
            ];
            expect(expectedOutputJsonFile).to.deep.equal(outputJsonFile);
        });

    });

    // describe('Compile Circuit', () => {
    //     it('Success test', async function () {
    //         console.log("Hello compilation...")
    //         console.log("End compilation\n")
    //     });

    // });
});