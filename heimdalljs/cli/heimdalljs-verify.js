#!/usr/bin/env node
const {program} = require("commander");
const fs = require("fs/promises");
const {RangePresentation} = require("../src/presentation/range");
const {PolygonPresentation} = require("../src/presentation/polygon");
const {getRevocationRoot} = require("./util");
const {poseidonHash} = require("../src/crypto/poseidon");
const {AttributePresentation} = require("../src/presentation/attribute");
const {PresentationTypes} = require("../src/presentation/presentation");
const {DelegationPresentation} = require("../src/presentation/delegation");

program.arguments("<path>");

const checkPresentation = async (path, options) => {
    console.debug = function() {};
    try {
        let presentationJSON = JSON.parse(await fs.readFile(path, "utf8"));
        let presentation;
        switch (presentationJSON.type) {
            case PresentationTypes.delegation:
                presentation = DelegationPresentation.restore(presentationJSON);
                break;
            case PresentationTypes.attribute:
                presentation = AttributePresentation.restore(presentationJSON);
                break;
            case PresentationTypes.polygon:
                presentation = PolygonPresentation.restore(presentationJSON);
                break;
            case PresentationTypes.range:
                presentation = RangePresentation.restore(presentationJSON);
                break;
        }
        console.debug('presentation', presentation)
        let revRoot = await getRevocationRoot(presentation.output.meta.revocationRegistry);
        console.debug('revRoot', revRoot)
        console.debug("presentation.verify", presentation.verify.toString())
        let valid = await presentation.verify(poseidonHash, undefined, revRoot);
        console.debug('valid', valid)
        return valid;
    } catch (err) {
        return Promise.reject(err);
    }
};

program.action((path, options) => {
    checkPresentation(path, options).then(res => {
        console.log(res);
        process.exit();
    }).catch(res => {
        console.log(res);
        process.exit();
    });
});

program.parse(process.argv);