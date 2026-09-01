/**
 * **Los dos casos de diseño del consumidor** (Fase 4, lote 4-6 · plan §7): la
 * prueba de que el puerto `RelationsDriver` + `defineRelationsConfig` sirven
 * para los DOS casos que nombra el roadmap, con **tablas ficticias del
 * consumidor** que demuestran el mapeo (dominio del consumidor → API del
 * paquete). No queda abstracto: se ve qué fila del consumidor produce qué
 * `relate`, y qué pregunta del consumidor es qué `check`.
 *
 * Corre con el DOBLE en memoria (`makeRelationsDriver`) + `RelationsManager`,
 * que es lo que vale para las tablas ficticias (regla del lote): el MODELO
 * fusionado y el store real ya se juzgan en `relations_openfga`/`relations_bridge`.
 *
 *  1. **Compartir un documento estilo Drive = ReBAC de OBJETOS** — `document`
 *     con `owner ⊆ editor ⊆ viewer` (includes) y equipos por `group#member`
 *     (usersets), particionado por tenant. Es el caso que da sentido a
 *     `relations/`.
 *  2. **«Llave COGNITIV» a un espacio** — si la llave es una RELACIÓN sobre un
 *     objeto `space` (no un scope), encaja como un tipo de objeto más
 *     (`holder`, con `admin ⊆ holder`). Y se DEJA ESCRITO lo que el plan §7
 *     concluyó: si la «llave» fuese acceso a un SCOPE (heredado hacia abajo),
 *     eso lo resuelve `roles/`, NO `relations/` — este caso cubre la otra
 *     lectura, la de objeto.
 */
import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import { RelationsManager } from '../src/relations/manager.js'
import { defineRelationsConfig } from '../src/relations/define_relations_config.js'
import { makeRelationsDriver } from '../src/testing/relations_contract.js'
import type { RelObject, RelSubject, ScopeRef } from '../src/types.js'

const HOLDER_TYPES = ['user', 'admin', 'integration']

/** La config de relaciones del consumidor: `document` (Drive) + `space` (COGNITIV). */
function consumerRelationsConfig() {
  return defineRelationsConfig({
    objectTypes: [
      {
        type: 'document',
        relations: [
          { name: 'owner' },
          { name: 'editor', includes: ['owner'] },
          { name: 'viewer', includes: ['editor'] },
        ],
      },
      {
        type: 'space',
        relations: [{ name: 'admin' }, { name: 'holder', includes: ['admin'] }],
      },
    ],
    holderTypes: [...HOLDER_TYPES],
    database: { membersOf: true },
  })
}

function managerOn() {
  const config = consumerRelationsConfig()
  const capabilities = {
    singleCheckRelations: true,
    listObjectsInherited: false as const,
    usersetSubjects: true,
    membersOfNative: true,
    enumerateRelations: true,
    listObjectsTruncation: false,
  }
  const driver = makeRelationsDriver({ config, capabilities })
  return new RelationsManager(driver, config)
}

/* ─────────────────────────────────────────────────────────────────────────
 * CASO 1 · Compartir documento estilo Drive (ReBAC de objetos)
 * ───────────────────────────────────────────────────────────────────────── */

test.group('caso de diseño 1 · compartir documento estilo Drive', () => {
  // Tablas FICTICIAS del consumidor (lo que existe en SU base, no en el paquete):
  //
  //   drive_tenants(id)
  //   drive_users(id, tenant_id)
  //   drive_documents(id, tenant_id, owner_user_id)
  //   drive_groups(id, tenant_id)                       -- «equipos»
  //   drive_group_members(group_id, user_id)
  //   drive_document_shares(document_id, grantee, role) -- grantee = user|group
  //
  // El consumidor MAPEA cada fila a la API del paquete: la partición es el
  // tenant, el objeto es `document:<uuid>`, el sujeto es un holder (user) o un
  // userset (`group:<uuid>#member`), y la relación es el rol de Drive.

  test('un editor puede ver (editor ⊆ viewer); un viewer NO puede editar', async ({ assert }) => {
    const rel = managerOn()
    const tenant: ScopeRef = { type: 'organization', uuid: uuidv7() }
    const alice: RelSubject = { type: 'user', uuid: uuidv7() }
    const bob: RelSubject = { type: 'user', uuid: uuidv7() }
    const doc: RelObject = { type: 'document', id: uuidv7() }

    // drive_document_shares: (doc, alice, 'editor'), (doc, bob, 'viewer')
    await rel.relate(alice, 'editor', doc, tenant)
    await rel.relate(bob, 'viewer', doc, tenant)

    assert.isTrue(await rel.check(alice, 'viewer', doc, tenant), 'editor ve (includes)')
    assert.isTrue(await rel.check(alice, 'editor', doc, tenant))
    assert.isTrue(await rel.check(bob, 'viewer', doc, tenant))
    assert.isFalse(await rel.check(bob, 'editor', doc, tenant), 'un viewer no es editor')
  })

  test('compartir con un EQUIPO: los miembros del grupo heredan el acceso (userset)', async ({ assert }) => {
    const rel = managerOn()
    const tenant: ScopeRef = { type: 'organization', uuid: uuidv7() }
    const team: RelObject = { type: 'group', id: uuidv7() }
    const carol: RelSubject = { type: 'user', uuid: uuidv7() }
    const doc: RelObject = { type: 'document', id: uuidv7() }

    // drive_group_members: (team, carol)
    await rel.relate(carol, 'member', team, tenant)
    // drive_document_shares: (doc, team, 'viewer')  → grantee es un userset
    await rel.relate({ object: team, relation: 'member' }, 'viewer', doc, tenant)

    assert.isTrue(await rel.check(carol, 'viewer', doc, tenant), 'miembro del equipo ve el doc')
    // Y un no-miembro no:
    const dave: RelSubject = { type: 'user', uuid: uuidv7() }
    assert.isFalse(await rel.check(dave, 'viewer', doc, tenant))
  })

  test('el tenant AÍSLA: el mismo documento en otro tenant no concede', async ({ assert }) => {
    const rel = managerOn()
    const acme: ScopeRef = { type: 'organization', uuid: uuidv7() }
    const globex: ScopeRef = { type: 'organization', uuid: uuidv7() }
    const eve: RelSubject = { type: 'user', uuid: uuidv7() }
    const doc: RelObject = { type: 'document', id: uuidv7() }

    await rel.relate(eve, 'viewer', doc, acme)
    assert.isTrue(await rel.check(eve, 'viewer', doc, acme))
    assert.isFalse(await rel.check(eve, 'viewer', doc, globex), 'otra partición, sin acceso')
  })
})

/* ─────────────────────────────────────────────────────────────────────────
 * CASO 2 · «Llave COGNITIV» a un espacio (ReBAC de objetos)
 * ───────────────────────────────────────────────────────────────────────── */

test.group('caso de diseño 2 · llave COGNITIV a un espacio', () => {
  // Tablas FICTICIAS del consumidor:
  //
  //   cognitiv_tenants(id)
  //   cognitiv_spaces(id, tenant_id)
  //   cognitiv_keys(id, space_id, subject_user_id, level)  -- level = holder|admin
  //   cognitiv_space_teams(space_id, group_id)
  //
  // Una «llave» = una fila de cognitiv_keys ⇒ `relate(user, level, space:<id>, tenant)`.
  // `admin ⊆ holder`: un administrador del espacio también es titular.

  test('una llave da acceso al espacio; admin ⊆ holder', async ({ assert }) => {
    const rel = managerOn()
    const tenant: ScopeRef = { type: 'organization', uuid: uuidv7() }
    const space: RelObject = { type: 'space', id: uuidv7() }
    const holder: RelSubject = { type: 'user', uuid: uuidv7() }
    const admin: RelSubject = { type: 'admin', uuid: uuidv7() }

    // cognitiv_keys: (space, holder, 'holder'), (space, admin, 'admin')
    await rel.relate(holder, 'holder', space, tenant)
    await rel.relate(admin, 'admin', space, tenant)

    assert.isTrue(await rel.check(holder, 'holder', space, tenant))
    assert.isTrue(await rel.check(admin, 'holder', space, tenant), 'admin es también holder (includes)')
    // Sin llave, sin acceso.
    const outsider: RelSubject = { type: 'user', uuid: uuidv7() }
    assert.isFalse(await rel.check(outsider, 'holder', space, tenant))
  })

  test('un EQUIPO con llave: los miembros son titulares (userset), y membersOf los enumera', async ({ assert }) => {
    const rel = managerOn()
    const tenant: ScopeRef = { type: 'organization', uuid: uuidv7() }
    const space: RelObject = { type: 'space', id: uuidv7() }
    const team: RelObject = { type: 'group', id: uuidv7() }
    const m1: RelSubject = { type: 'user', uuid: uuidv7() }
    const m2: RelSubject = { type: 'user', uuid: uuidv7() }

    await rel.relate(m1, 'member', team, tenant)
    await rel.relate(m2, 'member', team, tenant)
    // cognitiv_space_teams: (space, team) con nivel holder
    await rel.relate({ object: team, relation: 'member' }, 'holder', space, tenant)

    assert.isTrue(await rel.check(m1, 'holder', space, tenant))
    assert.isTrue(await rel.check(m2, 'holder', space, tenant))
    // La membresía TRANSITIVA del equipo, para un panel de administración:
    const members = await rel.membersOf(team, 'member', tenant)
    const uuids = members.subjects.map((s) => ('uuid' in s ? s.uuid : ''))
    assert.includeMembers(uuids, [m1.uuid, m2.uuid])
  })

  test('la «llave como SCOPE» NO es este puerto: se documenta que es roles/', async ({ assert }) => {
    // Plan §7: si «entrar a un espacio» fuese acceso a un SCOPE heredado hacia
    // abajo, lo resuelve `roles/` (un grant en el scope del espacio), no
    // `relations/`. Este caso cubre la lectura de OBJETO; la de scope no toca
    // este puerto. Lo dejamos como constancia ejecutable de la frontera.
    const rel = managerOn()
    const tenant: ScopeRef = { type: 'organization', uuid: uuidv7() }
    // `scope` es un tipo RESERVADO de facts: F-05 lo rechaza como objeto de
    // relación (no se puede «relacionar con un scope» por este puerto).
    let threw = false
    try {
      await rel.relate({ type: 'user', uuid: uuidv7() }, 'holder', { type: 'scope', id: uuidv7() }, tenant)
    } catch (error: any) {
      threw = true
      assert.equal(error.status, 422)
    }
    assert.isTrue(threw, 'un scope no es un objeto de relaciones (F-05): eso es roles/')
  })
})
