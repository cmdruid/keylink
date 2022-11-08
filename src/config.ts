export interface KeyConfig {
  name : string
  hrp  : string
  wif  : number
  version : {
    public  : number
    private : number
  },
}

const KeyConfigs : KeyConfig[] = [
  {
    name : 'bitcoin',
    hrp  : 'bc',
    wif  : 0x80,
    version : {
      public  : 0x0488b21e,
      private : 0x0488ade4,
    },
  }
]


export function getConfig(configName : string) : KeyConfig {
  const result = Object.values(KeyConfigs).find(({ name }) => name === configName)
  if (result === undefined) {
    throw TypeError('Key configuration does not exist for type: ' + configName)
  }
  return result
}