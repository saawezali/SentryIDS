export namespace config {
	
	export class Config {
	    confidence_threshold: number;
	    default_interface: string;
	    max_alerts_in_memory: number;
	    db_path: string;
	    theme: string;
	
	    static createFrom(source: any = {}) {
	        return new Config(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.confidence_threshold = source["confidence_threshold"];
	        this.default_interface = source["default_interface"];
	        this.max_alerts_in_memory = source["max_alerts_in_memory"];
	        this.db_path = source["db_path"];
	        this.theme = source["theme"];
	    }
	}

}

export namespace store {
	
	export class Alert {
	    ID: number;
	    // Go type: time
	    Timestamp: any;
	    SrcIP: string;
	    DstIP: string;
	    SrcPort: number;
	    DstPort: number;
	    Protocol: string;
	    AttackType: string;
	    Confidence: number;
	    Severity: string;
	
	    static createFrom(source: any = {}) {
	        return new Alert(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ID = source["ID"];
	        this.Timestamp = this.convertValues(source["Timestamp"], null);
	        this.SrcIP = source["SrcIP"];
	        this.DstIP = source["DstIP"];
	        this.SrcPort = source["SrcPort"];
	        this.DstPort = source["DstPort"];
	        this.Protocol = source["Protocol"];
	        this.AttackType = source["AttackType"];
	        this.Confidence = source["Confidence"];
	        this.Severity = source["Severity"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

