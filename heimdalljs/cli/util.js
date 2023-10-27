const got = require("got");
const {merklePoseidon} = require("../src/crypto/poseidon");
const fs = require("fs/promises");
const path = require("path");
const {stringifyBigInts} = require("../src/util");
const {exec, execSync} = require("child_process");
const MAX_POLYGON_SIZE = 50;

const getSecretKey = async (secretKeyPath) => {
    try {
        let secretKey;
        if (typeof secretKeyPath !== "undefined") {
            secretKey = await fs.readFile(secretKeyPath, "utf8");
            secretKey = secretKey.split("\n")[0];
        }
        return Promise.resolve(secretKey);
    } catch (err) {
        return Promise.reject(err);
    }
};

const parsePolygon = (polygon) => {
    let vertx = new Array(MAX_POLYGON_SIZE).fill(Math.floor(polygon[polygon.length - 1][0] * (10 ** 7)));
    let verty = new Array(MAX_POLYGON_SIZE).fill(Math.floor(polygon[polygon.length - 1][1] * (10 ** 7)));
    for (let i = 0; i < polygon.length; i++) {
        vertx[i] = Math.floor(polygon[i][0] * (10 ** 7));
        verty[i] = Math.floor(polygon[i][1] * (10 ** 7));
    }
    return {vertx: vertx, verty: verty};
};

const getRevocationRoot = async (source) => {
    let response = await got(source + "/revocation_root.json").catch(err => {
        return Promise.reject(err);
    });
    return Promise.resolve(JSON.parse(response.body));
};

const getRevocationTree = async (treeName, source) => {
    try {
        let registryObject;
        if (typeof treeName !== "undefined") {
            registryObject = await fs.readFile(treeName, "utf8");
            console.log("Tree");
            registryObject = JSON.parse(registryObject);
        } else {
            let response = await got(source + "/revocation_registry.json");
            registryObject = JSON.parse(response.body);
        }
        let revocationTree = merklePoseidon([], registryObject.tree);
        return Promise.resolve(revocationTree);
    } catch (err) {
        return Promise.reject(err);
    }
};

const pushGitRevocation = (destination) => {
    let reg = path.join(destination, "revocation_registry.json");
    let roo = path.join(destination, "revocation_root.json");
    let sig = path.join(destination, "revocation_signature.json");
    exec(`git pull && git add ${reg} ${roo} ${sig} && git commit -m "creating revocation registry" && git push`,
        (error, stdout, stderr) => {
            if (error) {
                console.log(`error: ${error.message}`);
                return;
            }
            if (stderr) {
                console.log(`stderr: ${stderr}`);
                return;
            }
            console.log(`stdout: ${stdout}`);
        });
};


/*
1) cd /
2) git clone https://github.com/ermolaev1337/test-revoc.git
3) cd test-revoc
4) git pull
5) read the tree
6) OPTIONAL: update the file of the tree
7) OPTIONAL: git commit -m "sdfsdfd"
8) OPTIONAL: git push
 */

const handleError = (error, stdout, stderr) => {
    if (error) {
        console.error(`error: ${error.message}`);
    }
    if (stderr) {
        console.error(`stderr: ${stderr}`);
    }
    console.log(`stdout: ${stdout}`);
};

const initTree = () => {
    execSync(`
    cd / &&
    git -C test-revoc pull || git clone https://github.com/ermolaev1337/test-revoc.git
    `, handleError);
};

const updateTree = () => {
    let reg = "/test-revoc/revocation_registry.json";
    let roo = "/test-revoc/revocation_root.json";
    const username = 'ermolaev1337';
    const token = process.env.GITHUB_TOKEN;
    const repoUrl = `https://${username}:${token}@github.com/ermolaev1337/test-revoc.git`;
    execSync(`
    cd /test-revoc &&
    git config --global user.email "heimdall@uni.lu" &&
    git config --global user.name "Heimdall" &&
    git add ${reg} ${roo} &&
    git commit -m 'Update revocation registry' &&
    git push ${repoUrl}
    `, handleError);
};

const writeFilesRevocation = async (reg, destination) => {
    reg.tree.leaves = stringifyBigInts(reg.tree.leaves);
    reg.tree.data = stringifyBigInts(reg.tree.data);
    if (typeof reg.signature !== "undefined") {
        reg.signature = stringifyBigInts(reg.signature);
        await fs.writeFile(path.join(destination, "revocation_signature.json"), JSON.stringify(reg.signature))
            .catch(console.log);
    }
    await fs.writeFile(path.join(destination, "revocation_registry.json"), JSON.stringify(reg)).catch(console.log);
    await fs.writeFile(path.join(destination, "revocation_root.json"), JSON.stringify(reg.tree.root))
        .catch(console.log);

    return Promise.resolve(true);
};

module.exports = {
    parsePolygon, getRevocationTree, getSecretKey, writeFilesRevocation, pushGitRevocation, updateTree,
    getRevocationRoot, initTree
};