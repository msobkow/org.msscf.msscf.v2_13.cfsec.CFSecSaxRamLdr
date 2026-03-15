// Description: Java 11 XML SAX Parser for CFSec.

/*
 *	org.msscf.msscf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal CFSec 2.13 Security Services
 *	
 *	Copyright 2016-2026 Mark Stephen Sobkow
 *	
 *	This file is part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *
 *	Manufactured by MSS Code Factory 2.12
 */

package org.msscf.msscf.v2_13.cfsec.CFSecSaxRamLdr;

import org.apache.log4j.*;
import org.msscf.msscf.v2_13.cflib.CFLib.*;
import org.msscf.msscf.v2_13.cflib.CFLib.xml.*;
import org.msscf.msscf.v2_13.cfsec.CFSec.*;

import org.msscf.msscf.v2_13.cfsec.CFSecObj.*;
import org.msscf.msscf.v2_13.cfsec.CFSecRam.*;
import org.msscf.msscf.v2_13.cfsec.CFSecSaxLoader.*;

public class CFSecSaxRamLdr
	extends CFSecSaxLdr
{
	private static ICFLibMessageLog log = new CFLibConsoleMessageLog();

	// Constructors

	public CFSecSaxRamLdr() {
		super( log );
	}

	// main() entry point

	public static void main( String args[] ) {
		final String S_ProcName = "CFSecSaxRamLdr.main() ";
		initConsoleLog();
		int numArgs = args.length;
		if( numArgs >= 2 ) {
			ICFSecSchema cFSecSchema = new CFSecRamSchema();
			ICFSecSchemaObj cFSecSchemaObj = new CFSecSchemaObj();
			cFSecSchemaObj.setBackingStore( cFSecSchema );
			CFSecSaxLdr cli = new CFSecSaxRamLdr();
			CFSecSaxLoader loader = cli.getSaxLoader();
			loader.setSchemaObj( cFSecSchemaObj );
			String url = args[1];
			try {
				cFSecSchema.connect( "system", "system", "system", "system" );
				cFSecSchema.rollback();
				cFSecSchema.beginTransaction();
				cFSecSchemaObj.setSecCluster( cFSecSchemaObj.getClusterTableObj().getSystemCluster() );
				cFSecSchemaObj.setSecTenant( cFSecSchemaObj.getTenantTableObj().getSystemTenant() );
				cFSecSchemaObj.setSecSession( cFSecSchemaObj.getSecSessionTableObj().getSystemSession() );
				CFSecAuthorization auth = new CFSecAuthorization();
				auth.setSecCluster( cFSecSchemaObj.getSecCluster() );
				auth.setSecTenant( cFSecSchemaObj.getSecTenant() );
				auth.setSecSession( cFSecSchemaObj.getSecSession() );
				cFSecSchemaObj.setAuthorization( auth );
				loader.setUseCluster( cFSecSchemaObj.getSecCluster() );
				loader.setUseTenant( cFSecSchemaObj.getSecTenant() );
				applyLoaderOptions( loader, args[0] );
				cli.evaluateRemainingArgs( args, 2 );
				loader.parseFile( url );
				cFSecSchema.commit();
				cFSecSchema.disconnect( true );
			}
			catch( Exception e ) {
				log.message( S_ProcName + "EXCEPTION: Could not parse XML file \"" + url + "\": " + e.getMessage() );
				e.printStackTrace( System.out );
			}
			catch( Error e ) {
				log.message( S_ProcName + "ERROR: Could not parse XML file \"" + url + "\": " + e.getMessage() );
				e.printStackTrace( System.out );
			}
			finally {
				if( cFSecSchema.isConnected() ) {
					cFSecSchema.rollback();
					cFSecSchema.disconnect( false );
				}
			}
		}
		else {
			log.message( S_ProcName + "ERROR: Expected at least two argument specifying the loader options and the name of the XML file to parse.  The first argument may be empty." );
		}
	}

	// Initialize the console log

	protected static void initConsoleLog() {
//		Layout layout = new PatternLayout(
//				"%d{ISO8601}"		// Start with a timestamp
//			+	" %-5p"				// Include the severity
//			+	" %C.%M"			// pkg.class.method()
//			+	" %F[%L]"			// File[lineNumber]
//			+	": %m\n" );			// Message text
//		BasicConfigurator.configure( new ConsoleAppender( layout, "System.out" ) );
	}

	// Evaluate remaining arguments

	public void evaluateRemainingArgs( String[] args, int consumed ) {
		// There are no extra arguments for the RAM "database" instance
		if( args.length > consumed ) {
			log.message( "CFSecSaxRamLdr.evaluateRemainingArgs() WARNING No extra arguments are expected for a RAM database instance, but "
				+ Integer.toString( args.length - consumed )
				+ " extra arguments were specified.  Extra arguments ignored." );
		}
	}

}
