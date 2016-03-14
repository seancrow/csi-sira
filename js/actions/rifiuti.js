/**
 * Copyright 2016, GeoSolutions Sas.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

const SELECT_RIFIUTO = 'SELECT_RIFIUTO';

function selectRifiuto(id) {
    return {
        type: SELECT_RIFIUTO,
        id_rifiuto: id
    };
}

module.exports = {
    SELECT_RIFIUTO,
    selectRifiuto
};